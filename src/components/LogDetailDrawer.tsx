import React from 'react';
import { FirewallLog } from '../types';
import { 
  X, 
  ShieldAlert, 
  ShieldCheck, 
  Sparkles, 
  ShieldBan, 
  Copy, 
  Check, 
  Globe, 
  Server, 
  Activity,
  Layers,
  FileCode
} from 'lucide-react';
import { getPortServiceName } from '../utils/geoData';

interface LogDetailDrawerProps {
  log: FirewallLog | null;
  onClose: () => void;
  onAiTriage: (log: FirewallLog) => void;
  onGenerateRule: (ip: string) => void;
  onFilterIp: (ip: string) => void;
}

export const LogDetailDrawer: React.FC<LogDetailDrawerProps> = ({
  log,
  onClose,
  onAiTriage,
  onGenerateRule,
  onFilterIp,
}) => {
  const [copied, setCopied] = React.useState(false);

  if (!log) return null;

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(log.rawLog);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isDenied = log.action !== 'ALLOW';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
      <div 
        className="w-full max-w-xl bg-slate-950 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2">
            {isDenied ? (
              <ShieldAlert className="w-5 h-5 text-rose-400" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            )}
            <div>
              <h3 className="text-sm font-bold text-white font-mono">
                Log Inspection: {log.id}
              </h3>
              <p className="text-[11px] text-slate-400">
                {new Date(log.timestamp).toLocaleString()} ({log.firewallType})
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

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Verdict Banner */}
          <div
            className={`p-3 rounded-lg border flex items-center justify-between ${
              isDenied
                ? 'bg-rose-950/30 border-rose-800/60 text-rose-200'
                : 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-sm uppercase px-2 py-0.5 rounded bg-slate-900 border">
                {log.action}
              </span>
              <div>
                <div className="text-xs font-bold text-white">
                  Severity: {log.severity} • {log.threatCategory}
                </div>
                <div className="text-[11px] text-slate-300">
                  {log.threatDescription || 'Standard traffic rule evaluation'}
                </div>
              </div>
            </div>
          </div>

          {/* Network Packet Header Details */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-3">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Decoded Packet Headers</span>
            </h4>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/70">
                <span className="text-[10px] text-slate-500 block uppercase">Source (Client)</span>
                <span className="text-slate-100 font-bold text-sm block mt-0.5">{log.sourceIp}</span>
                <span className="text-slate-400 text-[11px]">Port: {log.sourcePort}</span>
                <div className="mt-1 text-[11px] text-cyan-400 flex items-center gap-1">
                  <span>{log.sourceCountry === 'LOCAL' ? '🛡️' : log.sourceCountry}</span>
                  <span>{log.sourceCountryName || 'Unknown Region'}</span>
                </div>
                <div className="text-[10px] text-slate-500 truncate mt-0.5">
                  {log.sourceAsn}
                </div>
              </div>

              <div className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/70">
                <span className="text-[10px] text-slate-500 block uppercase">Destination (Target)</span>
                <span className="text-slate-100 font-bold text-sm block mt-0.5">{log.destinationIp}</span>
                <span className="text-cyan-400 text-[11px] font-bold">Port: {log.destinationPort}</span>
                <div className="mt-1 text-[11px] text-slate-300">
                  Service: {getPortServiceName(log.destinationPort)}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">
                  Interface: {log.interface || 'eth0'}
                </div>
              </div>
            </div>

            {/* Protocol & Flags */}
            <div className="grid grid-cols-3 gap-2 text-xs font-mono">
              <div className="bg-slate-950/70 p-2 rounded border border-slate-800/60">
                <span className="text-[10px] text-slate-500 block">Protocol</span>
                <span className="text-white font-bold">{log.protocol}</span>
              </div>
              <div className="bg-slate-950/70 p-2 rounded border border-slate-800/60">
                <span className="text-[10px] text-slate-500 block">TCP Flags</span>
                <span className="text-cyan-300 font-bold">
                  {log.tcpFlags && log.tcpFlags.length > 0 ? log.tcpFlags.join(', ') : 'NONE'}
                </span>
              </div>
              <div className="bg-slate-950/70 p-2 rounded border border-slate-800/60">
                <span className="text-[10px] text-slate-500 block">Size / Packets</span>
                <span className="text-white font-bold">{log.bytes} B ({log.packets} pkts)</span>
              </div>
            </div>
          </div>

          {/* Firewall Policy & Rule Attribution */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-2">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-purple-400" />
              <span>Firewall Policy Attribution</span>
            </h4>

            <div className="bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/70 text-xs font-mono space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-400">Rule Name / ID:</span>
                <span className="text-white font-bold">{log.ruleName}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Firewall Engine:</span>
                <span className="text-slate-200">{log.firewallType}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Ingress Interface:</span>
                <span className="text-slate-200">{log.interface || 'eth0 / WAN'}</span>
              </div>
            </div>
          </div>

          {/* Raw Log Line */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-yellow-400" />
                <span>Raw Log Record</span>
              </h4>
              <button
                onClick={handleCopyRaw}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 text-[11px] text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
              {log.rawLog}
            </pre>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex flex-wrap items-center justify-between gap-2">
          <button
            onClick={() => {
              onFilterIp(log.sourceIp);
              onClose();
            }}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Filter All Logs from {log.sourceIp}
          </button>

          <div className="flex items-center gap-2">
            {isDenied && (
              <button
                onClick={() => {
                  onGenerateRule(log.sourceIp);
                  onClose();
                }}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-rose-950 hover:bg-rose-900 text-rose-200 border border-rose-800 text-xs font-semibold transition-colors"
              >
                <ShieldBan className="w-4 h-4" />
                <span>Block IP</span>
              </button>
            )}

            <button
              onClick={() => {
                onAiTriage(log);
                onClose();
              }}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md transition-all"
            >
              <Sparkles className="w-4 h-4 text-yellow-300" />
              <span>AI Triage Event</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
