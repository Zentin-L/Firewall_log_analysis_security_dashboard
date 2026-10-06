import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';
import { parseBatchLogs } from './src/utils/logParsers.ts';

dotenv.config();

// In-memory buffer for real-time external syslog/webhook ingestion
const ingestedLogsBuffer: any[] = [];
const MAX_INGEST_BUFFER = 500;

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '10mb' }));
  app.use(express.text({ limit: '10mb', type: ['text/*', 'application/x-www-form-urlencoded'] }));

  // 1. Health check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // 2. Syslog / Webhook Ingest Endpoint
  // External firewall log forwarders (Filebeat, syslog-ng, fluentd, curl) can POST here!
  app.post('/api/logs/ingest', (req, res) => {
    try {
      let rawContent = '';
      if (typeof req.body === 'string') {
        rawContent = req.body;
      } else if (Array.isArray(req.body)) {
        rawContent = JSON.stringify(req.body);
      } else if (typeof req.body === 'object') {
        rawContent = JSON.stringify(req.body);
      }

      const parsedLogs = parseBatchLogs(rawContent);
      if (parsedLogs.length > 0) {
        ingestedLogsBuffer.unshift(...parsedLogs);
        if (ingestedLogsBuffer.length > MAX_INGEST_BUFFER) {
          ingestedLogsBuffer.length = MAX_INGEST_BUFFER;
        }
      }

      res.json({
        success: true,
        receivedCount: parsedLogs.length,
        message: `Successfully ingested and parsed ${parsedLogs.length} firewall log events`,
        sampleParsed: parsedLogs[0] || null,
      });
    } catch (err: any) {
      console.error('Error in /api/logs/ingest:', err);
      res.status(500).json({ error: err.message || 'Failed to parse ingested logs' });
    }
  });

  // 3. Retrieve newly ingested logs
  app.get('/api/logs/latest', (req, res) => {
    const logs = [...ingestedLogsBuffer];
    res.json({ logs, count: logs.length });
  });

  // 4. Gemini AI Threat Analysis / Incident Triage Endpoint
  app.post('/api/gemini/analyze-threat', async (req, res) => {
    try {
      const ai = getGeminiClient();
      if (!ai) {
        return res.status(503).json({
          error: 'Gemini API key is not configured. Please check your settings.',
        });
      }

      const { logOrAlert } = req.body;
      if (!logOrAlert) {
        return res.status(400).json({ error: 'Missing logOrAlert data in request body' });
      }

      const prompt = `You are a Principal Security Operations Center (SOC) Analyst and Threat Intelligence specialist.
Analyze the following firewall log event or correlated security alert and provide an authoritative security triage:

Event Data:
${JSON.stringify(logOrAlert, null, 2)}

Provide your response in strict JSON conforming to the requested schema.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
        config: {
          systemInstruction:
            'You are an elite cybersecurity SOC analyst. Analyze firewall network logs, identify CVE vulnerabilities, MITRE ATT&CK techniques, evaluate malicious intent, and generate concrete copy-pasteable firewall remediation rules (iptables, AWS WAF, Cisco ACL, pfSense, Cloudflare).',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: {
                type: Type.STRING,
                description: 'Clear, 2-sentence executive summary of the threat',
              },
              threatLevel: {
                type: Type.STRING,
                description: 'CRITICAL, HIGH, MEDIUM, LOW, or INFO',
              },
              mitreAttack: {
                type: Type.OBJECT,
                properties: {
                  tactic: { type: Type.STRING, description: 'e.g. Initial Access, Reconnaissance' },
                  technique: { type: Type.STRING, description: 'e.g. T1046 Network Service Discovery' },
                  id: { type: Type.STRING, description: 'e.g. T1046' },
                },
                required: ['tactic', 'technique', 'id'],
              },
              rootCauseAnalysis: {
                type: Type.STRING,
                description: 'Technical explanation of what the attacker is probing and why this traffic was triggered',
              },
              attackerProfile: {
                type: Type.OBJECT,
                properties: {
                  origin: { type: Type.STRING, description: 'Source country or infrastructure context' },
                  intent: { type: Type.STRING, description: 'Probable attacker goal' },
                  sophistication: {
                    type: Type.STRING,
                    description: 'Script Kiddie, Automated Botnet, Targeted APT, Commercial Scanner, or Unknown',
                  },
                },
                required: ['origin', 'intent', 'sophistication'],
              },
              recommendedMitigation: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'Step-by-step mitigation actions for network security engineers',
              },
              firewallRules: {
                type: Type.OBJECT,
                properties: {
                  iptables: { type: Type.STRING, description: 'Exact command to drop this source IP' },
                  awsWaf: { type: Type.STRING, description: 'AWS WAF IP Set / NACL rule definition' },
                  ciscoAcl: { type: Type.STRING, description: 'Cisco ASA / IOS access-list entry' },
                  pfsense: { type: Type.STRING, description: 'pfSense quick drop rule description' },
                  cloudflare: { type: Type.STRING, description: 'Cloudflare WAF Expression rule' },
                },
              },
            },
            required: ['summary', 'threatLevel', 'rootCauseAnalysis', 'attackerProfile', 'recommendedMitigation', 'firewallRules'],
          },
        },
      });

      const parsed = JSON.parse(response.text || '{}');
      res.json({ result: parsed });
    } catch (err: any) {
      console.error('Error in /api/gemini/analyze-threat:', err);
      res.status(500).json({ error: err.message || 'Failed to analyze threat with Gemini' });
    }
  });

  // 5. Gemini AI Natural Language Query & SOC Copilot
  app.post('/api/gemini/query-logs', async (req, res) => {
    try {
      const ai = getGeminiClient();
      if (!ai) {
        return res.status(503).json({
          error: 'Gemini API key is not configured. Please check your settings.',
        });
      }

      const { userQuery, recentSummary } = req.body;
      if (!userQuery) {
        return res.status(400).json({ error: 'Missing userQuery' });
      }

      const prompt = `A security analyst is asking a question about their firewall logs.
User Question: "${userQuery}"

Current Log Snapshot Overview:
${JSON.stringify(recentSummary || {}, null, 2)}

Provide an answer in JSON format with:
1. answer: Natural language explanation and findings based on firewall telemetry.
2. suggestedFilters: Optional filter state suggestion to apply to the dashboard (action, protocol, severity, threatCategory, port, search).
3. recommendedAction: Suggested immediate operational step.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
        config: {
          systemInstruction:
            'You are an AI Security Copilot for a Firewall Analytics Dashboard. Explain log trends, pinpoint anomalous traffic, identify malicious patterns, and translate user queries into concrete dashboard filter parameters.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              answer: { type: Type.STRING, description: 'Analyst explanation of what the telemetry indicates' },
              suggestedFilters: {
                type: Type.OBJECT,
                properties: {
                  action: { type: Type.STRING, description: 'ALLOW, BLOCK, DROP, REJECT or empty' },
                  protocol: { type: Type.STRING, description: 'TCP, UDP, ICMP, etc or empty' },
                  severity: { type: Type.STRING, description: 'CRITICAL, HIGH, MEDIUM, LOW, INFO or empty' },
                  threatCategory: { type: Type.STRING, description: 'PORT_SCAN, BRUTE_FORCE, DDOS_FLOOD, EXPLOIT_PROBE, etc' },
                  search: { type: Type.STRING, description: 'Keyword or IP string' },
                  destinationPort: { type: Type.NUMBER, description: 'Target port number' },
                },
              },
              recommendedAction: { type: Type.STRING, description: 'Next operational step for the analyst' },
            },
            required: ['answer'],
          },
        },
      });

      const parsed = JSON.parse(response.text || '{}');
      res.json({ result: parsed });
    } catch (err: any) {
      console.error('Error in /api/gemini/query-logs:', err);
      res.status(500).json({ error: err.message || 'Failed to process natural language query' });
    }
  });

  // 6. Gemini AI SOC Shift Handover Report Generator
  app.post('/api/gemini/soc-report', async (req, res) => {
    try {
      const ai = getGeminiClient();
      if (!ai) {
        return res.status(503).json({
          error: 'Gemini API key is not configured. Please check your settings.',
        });
      }

      const { stats, alerts, topAttackers, topPorts } = req.body;

      const prompt = `Generate a high-impact, professional SOC Shift Handover Briefing & Security Executive Summary based on the following firewall telemetry:

Telemetry Data:
- Total Ingested Events: ${stats?.totalLogs || 0}
- Blocked / Denied Rate: ${stats?.blockRate || 0}% (${stats?.blockedCount || 0} blocked / dropped)
- Active Security Alerts: ${alerts?.length || 0}
- Critical Incidents: ${stats?.criticalThreatCount || 0}
- Top Attacking Sources: ${JSON.stringify(topAttackers?.slice(0, 5) || [])}
- Most Targeted Ports: ${JSON.stringify(topPorts?.slice(0, 5) || [])}
- Active Correlated Incidents: ${JSON.stringify(alerts?.slice(0, 4) || [])}

Generate a thorough, formatted Markdown report suitable for CISO and senior SecOps leadership. Include:
1. Executive Posture & Threat Level
2. Key Attack Vectors & Observations (Port scans, brute-force, database probes)
3. Perimeter Rule Efficacy & False Positive Assessment
4. Immediate Actionable Recommendations (ACL updates, WAF rules, IP blocklists)`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
        config: {
          systemInstruction:
            'You are a Chief Information Security Officer (CISO) and Lead SOC Architect. Write concise, executive-level yet technically rigorous incident summary briefings.',
        },
      });

      res.json({ report: response.text });
    } catch (err: any) {
      console.error('Error in /api/gemini/soc-report:', err);
      res.status(500).json({ error: err.message || 'Failed to generate SOC report' });
    }
  });

  // 7. Vite / Static Middleware
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ Firewall Analytics Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
