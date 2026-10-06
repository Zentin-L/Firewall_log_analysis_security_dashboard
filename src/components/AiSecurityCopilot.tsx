import React, { useState } from 'react';
import { 
  X, 
  Sparkles, 
  ShieldAlert, 
  Bot, 
  Send, 
  FileText, 
  Terminal, 
  Copy, 
  Check, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw,
  Layers,
  ArrowRight
} from 'lucide-react';
import { AiTriageResult, FirewallLog, SecurityAlert, DashboardStats, TopAttackerStat, TargetPortStat } from '../types';

interface AiSecurityCopilotProps {
  isOpen: boolean;
  onClose: () => void;
  selectedLogForTriage: FirewallLog | null;
  selectedAlertForTriage: SecurityAlert | null;
  stats: DashboardStats;
  topAttackers: TopAttackerStat[];
  topPorts: TargetPortStat[];
  onApplySuggestedFilters?: (filters: any) => void;
}

export const AiSecurityCopilot: React.FC<AiSecurityCopilotProps> = ({
  isOpen,
  onClose,
  selectedLogForTriage,
  selectedAlertForTriage,
  stats,
  topAttackers,
  topPorts,
  onApplySuggestedFilters,
}) => {
  const [activeTab, setActiveTab] = useState<'triage' | 'ask' | 'report'>('triage');
  
  // Triage state
  const [triageResult, setTriageResult] = useState<AiTriageResult | null>(null);
  const [isTriaging, setIsTriaging] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);

  // Natural language query state
  const [userQuery, setUserQuery] = useState('');
  const [isQuerying, setIsQuerying] = useState(false);
  const [chatHistory, setChatHistory] = useState<Array<{ role: 'user' | 'assistant'; text: string; filters?: any; recommendation?: string }>>([
    {
      role: 'assistant',
      text: 'Hello! I am your AI Security Copilot. Ask me anything about your current firewall traffic, anomalies, or threat signatures.',
    },
  ]);

  // SOC Report state
  const [socReport, setSocReport] = useState<string | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  if (!isOpen) return null;

  // Run Triage
  const handleRunTriage = async (customTarget?: any) => {
    const target = customTarget || selectedAlertForTriage || selectedLogForTriage;
    if (!target) return;

    setIsTriaging(true);
    setTriageError(null);
    try {
      const res = await fetch('/api/gemini/analyze-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logOrAlert: target }),
      });
      const data = await res.json();
      if (data.error) {
        setTriageError(data.error);
      } else if (data.result) {
        setTriageResult(data.result);
      }
    } catch (err: any) {
      setTriageError(err.message || 'Failed to analyze with Gemini');
    } finally {
      setIsTriaging(false);
    }
  };

  // Run Query
  const handleSendQuery = async () => {
    if (!userQuery.trim() || isQuerying) return;
    const query = userQuery.trim();
    setUserQuery('');
    setChatHistory((prev) => [...prev, { role: 'user', text: query }]);
    setIsQuerying(true);

    try {
      const res = await fetch('/api/gemini/query-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userQuery: query,
          recentSummary: {
            stats,
            topAttackers: topAttackers.slice(0, 5),
            topPorts: topPorts.slice(0, 5),
          },
        }),
      });
      const data = await res.json();
      if (data.result) {
        setChatHistory((prev) => [
          ...prev,
          {
            role: 'assistant',
            text: data.result.answer,
            filters: data.result.suggestedFilters,
            recommendation: data.result.recommendedAction,
          },
        ]);
      }
    } catch (err: any) {
      setChatHistory((prev) => [
        ...prev,
        { role: 'assistant', text: `Sorry, I encountered an error: ${err.message}` },
      ]);
    } finally {
      setIsQuerying(false);
    }
  };

  // Generate SOC Report
  const handleGenerateSocReport = async () => {
    setIsGeneratingReport(true);
    try {
      const res = await fetch('/api/gemini/soc-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          stats,
          topAttackers,
          topPorts,
          alerts: [],
        }),
      });
      const data = await res.json();
      if (data.report) {
        setSocReport(data.report);
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div 
        className="w-full max-w-4xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col h-[85vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/70">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/20">
              <Sparkles className="w-5 h-5 text-yellow-300" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">
                  Gemini AI Security Copilot
                </h3>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono font-bold">
                  gemini-3.7-flash
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Automated Incident Triage, MITRE ATT&CK Mapping & SOC Reporting
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-900/40 px-5">
          <button
            onClick={() => setActiveTab('triage')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'triage'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Incident Triage</span>
          </button>
          <button
            onClick={() => setActiveTab('ask')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'ask'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bot className="w-3.5 h-3.5" />
            <span>Natural Language Query</span>
          </button>
          <button
            onClick={() => {
              setActiveTab('report');
              if (!socReport) handleGenerateSocReport();
            }}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'report'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Executive SOC Shift Report</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5">
          {/* TAB 1: Incident Triage */}
          {activeTab === 'triage' && (
            <div className="space-y-4">
              {/* Context Selector / Action Trigger */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-xs">
                  <span className="text-slate-400 block mb-0.5">Target Context:</span>
                  <span className="text-white font-bold font-mono">
                    {selectedAlertForTriage
                      ? `Alert: ${selectedAlertForTriage.title}`
                      : selectedLogForTriage
                      ? `Log: ${selectedLogForTriage.sourceIp} -> :${selectedLogForTriage.destinationPort}`
                      : topAttackers[0]
                      ? `Top Attacker: ${topAttackers[0].ip} (${topAttackers[0].countryName})`
                      : 'Active Telemetry Overview'}
                  </span>
                </div>

                <button
                  id="btn-trigger-ai-triage"
                  onClick={() => handleRunTriage()}
                  disabled={isTriaging}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md transition-all flex items-center gap-1.5 shrink-0 cursor-pointer"
                >
                  {isTriaging ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Analyzing Telemetry...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
                      <span>{triageResult ? 'Re-Analyze Threat' : 'Analyze Threat with Gemini'}</span>
                    </>
                  )}
                </button>
              </div>

              {triageError && (
                <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>{triageError}</span>
                </div>
              )}

              {/* Triage Results Display */}
              {triageResult ? (
                <div className="space-y-4">
                  {/* Executive Summary */}
                  <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                        Executive Threat Assessment
                      </h4>
                      <span className="px-2.5 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800 text-xs font-mono font-bold">
                        {triageResult.threatLevel}
                      </span>
                    </div>
                    <p className="text-xs text-slate-200 leading-relaxed font-sans font-medium">
                      {triageResult.summary}
                    </p>
                  </div>

                  {/* MITRE & Attacker Profile Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {/* MITRE ATT&CK */}
                    {triageResult.mitreAttack && (
                      <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
                        <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5 text-purple-400" />
                          <span>MITRE ATT&CK Mapping</span>
                        </div>
                        <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-xs font-mono">
                          <div className="text-purple-300 font-bold">
                            {triageResult.mitreAttack.id}: {triageResult.mitreAttack.technique}
                          </div>
                          <div className="text-slate-400 text-[11px] mt-0.5">
                            Tactic: {triageResult.mitreAttack.tactic}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Attacker Profile */}
                    <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
                      <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                        <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                        <span>Attacker Profile</span>
                      </div>
                      <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-xs font-mono space-y-0.5">
                        <div className="text-slate-200">
                          <span className="text-slate-500">Sophistication: </span>
                          <span className="text-amber-400 font-bold">{triageResult.attackerProfile.sophistication}</span>
                        </div>
                        <div className="text-slate-300 text-[11px]">
                          <span className="text-slate-500">Intent: </span>
                          {triageResult.attackerProfile.intent}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Root Cause Analysis */}
                  <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                      Technical Root Cause & Protocol Analysis
                    </h4>
                    <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                      {triageResult.rootCauseAnalysis}
                    </p>
                  </div>

                  {/* Recommended Mitigations */}
                  <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
                    <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Recommended SecOps Mitigations</span>
                    </h4>
                    <ul className="space-y-1.5 text-xs text-slate-200">
                      {triageResult.recommendedMitigation.map((m, i) => (
                        <li key={i} className="flex items-start gap-2 bg-slate-950/60 p-2 rounded-lg border border-slate-800/60">
                          <span className="text-emerald-400 font-bold font-mono text-[11px]">{i + 1}.</span>
                          <span>{m}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Generated Firewall Rules */}
                  {triageResult.firewallRules && (
                    <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
                      <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Ready-to-Deploy Firewall Remediation Rules</span>
                      </h4>
                      <div className="space-y-2 text-xs font-mono">
                        {triageResult.firewallRules.iptables && (
                          <div>
                            <span className="text-[10px] text-slate-400 block mb-0.5 font-sans font-semibold">Linux iptables / UFW</span>
                            <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 text-cyan-300 overflow-x-auto">
                              {triageResult.firewallRules.iptables}
                            </pre>
                          </div>
                        )}
                        {triageResult.firewallRules.ciscoAcl && (
                          <div>
                            <span className="text-[10px] text-slate-400 block mb-0.5 font-sans font-semibold">Cisco ASA / FTD ACL</span>
                            <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 text-amber-300 overflow-x-auto">
                              {triageResult.firewallRules.ciscoAcl}
                            </pre>
                          </div>
                        )}
                        {triageResult.firewallRules.awsWaf && (
                          <div>
                            <span className="text-[10px] text-slate-400 block mb-0.5 font-sans font-semibold">AWS WAF / Security Group Rule</span>
                            <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 text-emerald-300 overflow-x-auto">
                              {triageResult.firewallRules.awsWaf}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-12 text-slate-400 text-xs flex flex-col items-center">
                  <Sparkles className="w-10 h-10 text-cyan-500 mb-3 animate-pulse" />
                  <span className="font-semibold text-slate-200">Ready for Deep AI Threat Triage</span>
                  <span className="text-slate-400 text-[11px] max-w-md mt-1">
                    Click &quot;Analyze Threat with Gemini&quot; above to decode the attack intent, pinpoint MITRE ATT&CK techniques, and generate custom firewall mitigation rules.
                  </span>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: Natural Language Query */}
          {activeTab === 'ask' && (
            <div className="flex flex-col h-full space-y-3">
              {/* Query Messages List */}
              <div className="flex-1 overflow-y-auto space-y-3 pr-1 max-h-[380px]">
                {chatHistory.map((msg, index) => (
                  <div
                    key={index}
                    className={`p-3.5 rounded-xl text-xs leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-cyan-950/50 border border-cyan-800/80 text-cyan-100 ml-8'
                        : 'bg-slate-900/90 border border-slate-800 text-slate-200 mr-8'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 mb-1 text-[11px] font-bold text-slate-400">
                      {msg.role === 'user' ? <span>Security Analyst</span> : <span className="text-cyan-400">Gemini Security Assistant</span>}
                    </div>
                    <p className="whitespace-pre-wrap">{msg.text}</p>

                    {/* Filter Action Pill */}
                    {msg.filters && (
                      <div className="mt-2.5 pt-2 border-t border-slate-800 flex items-center justify-between gap-2">
                        <span className="text-[11px] text-slate-400">
                          Suggested Dashboard Filter:
                        </span>
                        <button
                          onClick={() => {
                            onApplySuggestedFilters?.(msg.filters);
                            onClose();
                          }}
                          className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-semibold flex items-center gap-1"
                        >
                          <span>Apply Filter</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}

                {isQuerying && (
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                    <span>Gemini is analyzing the firewall log telemetry...</span>
                  </div>
                )}
              </div>

              {/* Input Bar */}
              <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
                <input
                  type="text"
                  placeholder="Ask e.g. 'What IP is probing our database ports?' or 'Show me all denied SSH attempts'"
                  value={userQuery}
                  onChange={(e) => setUserQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSendQuery()}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <button
                  id="btn-send-ai-query"
                  onClick={handleSendQuery}
                  disabled={!userQuery.trim() || isQuerying}
                  className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:pointer-events-none text-white text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Ask</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 3: SOC Shift Report */}
          {activeTab === 'report' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                    Executive Shift Handover & Security Posture Briefing
                  </h4>
                  <p className="text-xs text-slate-400">
                    Auto-generated CISO-level briefing synthesized from current firewall logs
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleGenerateSocReport}
                    disabled={isGeneratingReport}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isGeneratingReport ? 'animate-spin' : ''}`} />
                    <span>Regenerate</span>
                  </button>

                  {socReport && (
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(socReport);
                        setCopiedReport(true);
                        setTimeout(() => setCopiedReport(false), 2000);
                      }}
                      className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-colors"
                    >
                      {copiedReport ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedReport ? 'Copied' : 'Copy Report'}</span>
                    </button>
                  )}
                </div>
              </div>

              {isGeneratingReport ? (
                <div className="py-16 text-center text-slate-400 text-xs flex flex-col items-center">
                  <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mb-3" />
                  <span>Synthesizing Executive Shift Handover Report with Gemini...</span>
                </div>
              ) : socReport ? (
                <div className="bg-slate-950 p-4 sm:p-6 rounded-xl border border-slate-800 text-xs text-slate-200 leading-relaxed font-sans whitespace-pre-wrap">
                  {socReport}
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
