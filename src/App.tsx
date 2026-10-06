import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  FirewallLog, 
  FilterState, 
  DashboardStats, 
  TimelineDataPoint, 
  ProtocolStat, 
  TopAttackerStat, 
  TargetPortStat, 
  GeoThreatStat, 
  SecurityAlert 
} from './types';
import { generateInitialDataset, generateSingleRandomLog, detectSecurityAlerts, PRESET_DATASETS } from './utils/sampleData';
import { getPortServiceName } from './utils/geoData';
import { Header } from './components/Header';
import { KPICards } from './components/KPICards';
import { TrafficTimelineChart } from './components/TrafficTimelineChart';
import { ProtocolDonutChart } from './components/ProtocolDonutChart';
import { TopAttackerBarChart } from './components/TopAttackerBarChart';
import { TargetPortsChart } from './components/TargetPortsChart';
import { GeoThreatMap } from './components/GeoThreatMap';
import { AlertsPanel } from './components/AlertsPanel';
import { LogTable } from './components/LogTable';
import { LogDetailDrawer } from './components/LogDetailDrawer';
import { ConnectorModal } from './components/ConnectorModal';
import { AiSecurityCopilot } from './components/AiSecurityCopilot';
import { RuleGeneratorModal } from './components/RuleGeneratorModal';

export default function App() {
  // Main Telemetry Logs State
  const [logs, setLogs] = useState<FirewallLog[]>(() => generateInitialDataset(120));
  const [isStreaming, setIsStreaming] = useState(true);
  const [streamSpeed, setStreamSpeed] = useState(1500);

  // Filters State
  const [filters, setFilters] = useState<FilterState>({
    searchQuery: '',
    action: 'all',
    protocol: 'all',
    severity: 'all',
    threatCategory: 'all',
    timeRange: '1h',
    country: 'all',
  });

  // Modal / Drawer States
  const [isConnectorOpen, setIsConnectorOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [inspectingLog, setInspectingLog] = useState<FirewallLog | null>(null);
  const [ruleTargetIp, setRuleTargetIp] = useState<string | null>(null);
  const [triageTargetLog, setTriageTargetLog] = useState<FirewallLog | null>(null);
  const [triageTargetAlert, setTriageTargetAlert] = useState<SecurityAlert | null>(null);

  // 1. Live stream simulation effect
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const isThreat = Math.random() < 0.4;
      const newLog = generateSingleRandomLog(isThreat);
      setLogs((prev) => {
        const next = [newLog, ...prev];
        return next.slice(0, 400); // keep memory efficient
      });
    }, streamSpeed);

    return () => clearInterval(interval);
  }, [isStreaming, streamSpeed]);

  // 2. Poll server for newly ingested webhook logs
  useEffect(() => {
    const pollInterval = setInterval(async () => {
      try {
        const res = await fetch('/api/logs/latest');
        const data = await res.json();
        if (data.logs && data.logs.length > 0) {
          setLogs((prev) => {
            const existingIds = new Set(prev.map((l) => l.id));
            const newEntries = data.logs.filter((l: FirewallLog) => !existingIds.has(l.id));
            if (newEntries.length === 0) return prev;
            return [...newEntries, ...prev].slice(0, 400);
          });
        }
      } catch (e) {
        // Ignore background polling errors
      }
    }, 5000);

    return () => clearInterval(pollInterval);
  }, []);

  // 3. Automated Security Alerts Correlation
  const alerts = useMemo(() => {
    return detectSecurityAlerts(logs);
  }, [logs]);

  // 4. Executive Dashboard KPIs
  const stats: DashboardStats = useMemo(() => {
    let allowedCount = 0;
    let blockedCount = 0;
    let droppedCount = 0;
    let rejectedCount = 0;
    let totalBytes = 0;
    let totalPackets = 0;
    const sourceIps = new Set<string>();
    const destIps = new Set<string>();

    for (const l of logs) {
      if (l.action === 'ALLOW') allowedCount++;
      else if (l.action === 'DROP') droppedCount++;
      else if (l.action === 'BLOCK') blockedCount++;
      else if (l.action === 'REJECT') rejectedCount++;

      totalBytes += l.bytes || 0;
      totalPackets += l.packets || 1;
      sourceIps.add(l.sourceIp);
      destIps.add(l.destinationIp);
    }

    const totalLogs = logs.length;
    const totalDenied = blockedCount + droppedCount + rejectedCount;
    const blockRate = totalLogs > 0 ? (totalDenied / totalLogs) * 100 : 0;

    const criticalThreatCount = alerts.filter((a) => a.severity === 'CRITICAL').length;

    return {
      totalLogs,
      allowedCount,
      blockedCount,
      droppedCount,
      rejectedCount,
      blockRate,
      uniqueSourceIps: sourceIps.size,
      uniqueDestIps: destIps.size,
      totalBytes,
      totalPackets,
      activeThreatCount: alerts.length,
      criticalThreatCount,
    };
  }, [logs, alerts]);

  // 5. Timeline Chart Aggregation (12 time slices)
  const timelineData: TimelineDataPoint[] = useMemo(() => {
    if (logs.length === 0) return [];

    const numBuckets = 14;
    const now = Date.now();
    const spanMs = 60 * 60 * 1000; // 1 hour
    const bucketDuration = spanMs / numBuckets;

    const buckets = Array.from({ length: numBuckets }, (_, i) => {
      const bucketTime = now - (numBuckets - 1 - i) * bucketDuration;
      const date = new Date(bucketTime);
      return {
        timeLabel: `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`,
        timestamp: bucketTime,
        allowed: 0,
        blocked: 0,
        dropped: 0,
        total: 0,
        bytes: 0,
      };
    });

    for (const log of logs) {
      const logTime = new Date(log.timestamp).getTime();
      const ageMs = now - logTime;
      const bucketIndex = Math.min(numBuckets - 1, Math.max(0, Math.floor((spanMs - ageMs) / bucketDuration)));

      if (bucketIndex >= 0 && bucketIndex < numBuckets) {
        const b = buckets[bucketIndex];
        b.total += 1;
        b.bytes += log.bytes;
        if (log.action === 'ALLOW') b.allowed += 1;
        else if (log.action === 'DROP') b.dropped += 1;
        else b.blocked += 1;
      }
    }

    return buckets;
  }, [logs]);

  // 6. Protocol Donut Distribution
  const protocolStats: ProtocolStat[] = useMemo(() => {
    const counts: Record<string, { count: number; bytes: number }> = {};
    for (const l of logs) {
      if (!counts[l.protocol]) {
        counts[l.protocol] = { count: 0, bytes: 0 };
      }
      counts[l.protocol].count += 1;
      counts[l.protocol].bytes += l.bytes;
    }

    const total = logs.length || 1;
    const colors = ['#06b6d4', '#3b82f6', '#a855f7', '#ec4899', '#f97316', '#64748b'];

    return Object.entries(counts).map(([proto, val], idx) => ({
      protocol: proto,
      count: val.count,
      percentage: (val.count / total) * 100,
      bytes: val.bytes,
      color: colors[idx % colors.length],
    }));
  }, [logs]);

  // 7. Top Attacker IPs Ranking
  const topAttackers: TopAttackerStat[] = useMemo(() => {
    const map: Record<string, {
      country: string;
      countryName: string;
      asn: string;
      hits: number;
      blockedHits: number;
      topPort: number;
      threatCategory: any;
      severity: any;
      lastSeen: string;
    }> = {};

    for (const l of logs) {
      if (!map[l.sourceIp]) {
        map[l.sourceIp] = {
          country: l.sourceCountry === 'LOCAL' ? '🛡️' : l.sourceCountry || '🌐',
          countryName: l.sourceCountryName || 'Unknown',
          asn: l.sourceAsn || 'AS-UNASSIGNED',
          hits: 0,
          blockedHits: 0,
          topPort: l.destinationPort,
          threatCategory: l.threatCategory,
          severity: l.severity,
          lastSeen: l.timestamp,
        };
      }
      map[l.sourceIp].hits += 1;
      if (l.action !== 'ALLOW') {
        map[l.sourceIp].blockedHits += 1;
      }
    }

    return Object.entries(map)
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.blockedHits - a.blockedHits)
      .slice(0, 10);
  }, [logs]);

  // 8. Target Destination Ports Ranking
  const targetPortStats: TargetPortStat[] = useMemo(() => {
    const map: Record<number, { count: number; blockedCount: number }> = {};
    for (const l of logs) {
      if (!map[l.destinationPort]) {
        map[l.destinationPort] = { count: 0, blockedCount: 0 };
      }
      map[l.destinationPort].count += 1;
      if (l.action !== 'ALLOW') {
        map[l.destinationPort].blockedCount += 1;
      }
    }

    const total = logs.length || 1;
    return Object.entries(map)
      .map(([portStr, data]) => {
        const port = Number(portStr);
        return {
          port,
          service: getPortServiceName(port),
          count: data.count,
          blockedCount: data.blockedCount,
          percentage: (data.count / total) * 100,
        };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [logs]);

  // 9. Geo Threat Distribution
  const geoStats: GeoThreatStat[] = useMemo(() => {
    const map: Record<string, { name: string; total: number; blocked: number; topThreat: any }> = {};
    for (const l of logs) {
      const code = l.sourceCountry || 'US';
      if (!map[code]) {
        map[code] = {
          name: l.sourceCountryName || code,
          total: 0,
          blocked: 0,
          topThreat: l.threatCategory,
        };
      }
      map[code].total += 1;
      if (l.action !== 'ALLOW') {
        map[code].blocked += 1;
      }
    }

    return Object.entries(map).map(([countryCode, val]) => ({
      countryCode,
      countryName: val.name,
      totalEvents: val.total,
      blockedEvents: val.blocked,
      threatScore: val.blocked * 10,
      topThreat: val.topThreat,
    }));
  }, [logs]);

  // Filter Updates
  const handleUpdateFilters = useCallback((newFilters: Partial<FilterState>) => {
    setFilters((prev) => ({ ...prev, ...newFilters }));
  }, []);

  const handleResetFilters = useCallback(() => {
    setFilters({
      searchQuery: '',
      action: 'all',
      protocol: 'all',
      severity: 'all',
      threatCategory: 'all',
      timeRange: 'all',
      country: 'all',
    });
  }, []);

  // Export logs to CSV / JSON
  const handleExportLogs = (format: 'csv' | 'json') => {
    if (format === 'json') {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `firewall_logs_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } else {
      const headers = ['Timestamp', 'Action', 'Severity', 'SourceIP', 'SourcePort', 'DestinationIP', 'DestinationPort', 'Protocol', 'RuleName', 'Bytes', 'Packets', 'Country', 'ThreatCategory'];
      const rows = logs.map((l) => [
        l.timestamp,
        l.action,
        l.severity,
        l.sourceIp,
        l.sourcePort,
        l.destinationIp,
        l.destinationPort,
        l.protocol,
        `"${l.ruleName}"`,
        l.bytes,
        l.packets,
        l.sourceCountry || 'US',
        l.threatCategory,
      ]);
      const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', encodeURI(csvContent));
      downloadAnchor.setAttribute('download', `firewall_logs_${Date.now()}.csv`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }
  };

  const handleSelectPreset = (presetKey: string) => {
    const preset = PRESET_DATASETS[presetKey];
    if (preset) {
      setLogs(preset.logs);
      handleResetFilters();
    }
  };

  const handleAiTriageLog = (log: FirewallLog) => {
    setTriageTargetLog(log);
    setTriageTargetAlert(null);
    setIsCopilotOpen(true);
  };

  const handleAiTriageAlert = (alert: SecurityAlert) => {
    setTriageTargetAlert(alert);
    setTriageTargetLog(null);
    setIsCopilotOpen(true);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-white">
      {/* 1. Header Toolbar */}
      <Header
        isStreaming={isStreaming}
        onToggleStreaming={() => setIsStreaming(!isStreaming)}
        streamSpeed={streamSpeed}
        onChangeStreamSpeed={setStreamSpeed}
        onOpenConnector={() => setIsConnectorOpen(true)}
        onOpenCopilot={() => setIsCopilotOpen(true)}
        onSelectPreset={handleSelectPreset}
        onExportLogs={handleExportLogs}
        onClearLogs={() => setLogs([])}
        totalLogsCount={logs.length}
      />

      {/* 2. Main Content Dashboard */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-6 space-y-6">
        {/* Executive KPIs */}
        <KPICards
          stats={stats}
          onFilterByStatus={(action) => handleUpdateFilters({ action })}
          onFilterByThreats={() => handleUpdateFilters({ threatCategory: 'THREATS_ONLY' })}
        />

        {/* Traffic Timeline & Layer 4 Protocol Donut Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <TrafficTimelineChart
              data={timelineData}
              timeRange={filters.timeRange}
              onChangeTimeRange={(range) => handleUpdateFilters({ timeRange: range })}
            />
          </div>
          <div className="lg:col-span-1">
            <ProtocolDonutChart
              data={protocolStats}
              onSelectProtocol={(protocol) => handleUpdateFilters({ protocol })}
            />
          </div>
        </div>

        {/* Global Threat Map & Correlated Alerts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <GeoThreatMap
            data={geoStats}
            onSelectCountry={(countryCode) => handleUpdateFilters({ country: countryCode })}
          />
          <AlertsPanel
            alerts={alerts}
            onSelectAlertIp={(ip) => handleUpdateFilters({ selectedIp: ip })}
            onAiTriageAlert={handleAiTriageAlert}
            onGenerateRule={(ip) => setRuleTargetIp(ip)}
          />
        </div>

        {/* Top Attacking Sources & Target Port Heatmap */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <TopAttackerBarChart
            data={topAttackers}
            onSelectIp={(ip) => handleUpdateFilters({ selectedIp: ip })}
            onAnalyzeIp={(ip, attacker) => {
              setTriageTargetLog(logs.find((l) => l.sourceIp === ip) || null);
              setIsCopilotOpen(true);
            }}
            onGenerateRule={(ip) => setRuleTargetIp(ip)}
          />
          <TargetPortsChart
            data={targetPortStats}
            onSelectPort={(port) => handleUpdateFilters({ selectedPort: port })}
          />
        </div>

        {/* Real-time Decoded Log Table with Search and Granular Filtering */}
        <LogTable
          logs={logs}
          filters={filters}
          onUpdateFilters={handleUpdateFilters}
          onResetFilters={handleResetFilters}
          onSelectLog={(log) => setInspectingLog(log)}
          onAiTriageLog={handleAiTriageLog}
          onGenerateRule={(ip) => setRuleTargetIp(ip)}
        />
      </main>

      {/* 3. Inspection & Action Modals */}
      <LogDetailDrawer
        log={inspectingLog}
        onClose={() => setInspectingLog(null)}
        onAiTriage={handleAiTriageLog}
        onGenerateRule={(ip) => setRuleTargetIp(ip)}
        onFilterIp={(ip) => handleUpdateFilters({ selectedIp: ip })}
      />

      <ConnectorModal
        isOpen={isConnectorOpen}
        onClose={() => setIsConnectorOpen(false)}
        onIngestLogs={(newLogs) => {
          setLogs((prev) => [...newLogs, ...prev].slice(0, 400));
        }}
        onSelectPreset={handleSelectPreset}
      />

      <AiSecurityCopilot
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        selectedLogForTriage={triageTargetLog}
        selectedAlertForTriage={triageTargetAlert}
        stats={stats}
        topAttackers={topAttackers}
        topPorts={targetPortStats}
        onApplySuggestedFilters={(suggested) => {
          handleUpdateFilters({
            action: suggested.action || 'all',
            protocol: suggested.protocol || 'all',
            severity: suggested.severity || 'all',
            threatCategory: suggested.threatCategory || 'all',
            searchQuery: suggested.search || '',
            selectedPort: suggested.destinationPort || undefined,
          });
        }}
      />

      <RuleGeneratorModal
        isOpen={Boolean(ruleTargetIp)}
        onClose={() => setRuleTargetIp(null)}
        targetIp={ruleTargetIp || ''}
      />
    </div>
  );
}
