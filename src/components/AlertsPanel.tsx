import React from 'react';
import { SecurityAlert } from '../types';
import { 
  Flame, 
  ShieldAlert, 
  Sparkles, 
  ShieldBan, 
  Filter, 
  CheckCircle2, 
  ExternalLink,
  Clock,
  Crosshair
} from 'lucide-react';
import { getPortServiceName } from '../utils/geoData';

interface AlertsPanelProps {
  alerts: SecurityAlert[];
  onSelectAlertIp: (ip: string) => void;
  onAiTriageAlert: (alert: SecurityAlert) => void;
  onGenerateRule: (ip: string) => void;
}

export const AlertsPanel: React.FC<AlertsPanelProps> = ({
  alerts,
  onSelectAlertIp,
  onAiTriageAlert,
  onGenerateRule,
}) => {
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-extrabold animate-pulse">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2 py-0.5 rounded-full bg-yellow-950 text-yellow-300 border border-yellow-800 text-[10px] font-bold">
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 text-[10px]">
            LOW
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Flame className="w-4 h-4 text-amber-400" />
          <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
            Active Security Incidents
            <span className="text-xs px-2 py-0.5 rounded-full bg-amber-950 text-amber-400 border border-amber-800/60 font-mono font-bold">
              {alerts.length}
            </span>
          </h3>
        </div>
        <span className="text-[11px] text-slate-400">Rule-Correlated Telemetry</span>
      </div>

      <div className="flex-1 overflow-y-auto space-y-3 max-h-[320px] pr-1">
        {alerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs py-8 text-center">
            <CheckCircle2 className="w-8 h-8 text-emerald-500 mb-2" />
            <span className="font-semibold text-slate-300">Zero Active Perimeter Incidents</span>
            <span className="text-slate-500 text-[11px] mt-0.5">All ingested packets match expected baseline traffic.</span>
          </div>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.id}
              className="bg-slate-950/80 hover:bg-slate-800/80 border border-slate-800/90 hover:border-amber-700/60 rounded-lg p-3 transition-all"
            >
              <div className="flex items-start justify-between gap-2 mb-1.5">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    {getSeverityBadge(alert.severity)}
                    <h4 className="text-xs font-bold text-white">{alert.title}</h4>
                  </div>
                  {alert.mitreTechnique && (
                    <span className="inline-block text-[10px] text-cyan-400 font-mono bg-cyan-950/70 px-1.5 py-0.5 rounded border border-cyan-900/60 mt-1">
                      MITRE {alert.mitreTechnique}
                    </span>
                  )}
                </div>
                <div className="text-right font-mono text-[11px] text-slate-400 shrink-0">
                  <span className="text-white font-bold">{alert.eventCount}</span> blocked pkts
                </div>
              </div>

              <p className="text-xs text-slate-300 mb-2.5 leading-relaxed">
                {alert.description}
              </p>

              {/* Attacker Context & Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60">
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-slate-400 text-[11px]">Attacker:</span>
                  <span 
                    onClick={() => onSelectAlertIp(alert.sourceIp)}
                    className="font-bold text-cyan-400 hover:underline cursor-pointer"
                  >
                    {alert.sourceIp}
                  </span>
                  {alert.targetPorts.length > 0 && (
                    <span className="text-slate-400 text-[10px]">
                      (Port {alert.targetPorts.slice(0, 3).join(', ')}{alert.targetPorts.length > 3 ? '...' : ''})
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => onSelectAlertIp(alert.sourceIp)}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
                  >
                    <Filter className="w-3 h-3" />
                    <span>Filter</span>
                  </button>

                  <button
                    onClick={() => onGenerateRule(alert.sourceIp)}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 text-[11px] font-medium transition-colors"
                  >
                    <ShieldBan className="w-3 h-3" />
                    <span>Block IP</span>
                  </button>

                  <button
                    onClick={() => onAiTriageAlert(alert)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-[11px] font-semibold shadow-sm transition-all"
                  >
                    <Sparkles className="w-3 h-3 text-yellow-300" />
                    <span>AI Triage</span>
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
