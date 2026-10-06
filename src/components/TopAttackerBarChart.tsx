import React from 'react';
import { TopAttackerStat } from '../types';
import { ShieldAlert, Crosshair, Sparkles, Filter, ShieldBan } from 'lucide-react';
import { getPortServiceName } from '../utils/geoData';

interface TopAttackerBarChartProps {
  data: TopAttackerStat[];
  onSelectIp?: (ip: string) => void;
  onAnalyzeIp?: (ip: string, attacker: TopAttackerStat) => void;
  onGenerateRule?: (ip: string) => void;
}

export const TopAttackerBarChart: React.FC<TopAttackerBarChartProps> = ({
  data,
  onSelectIp,
  onAnalyzeIp,
  onGenerateRule,
}) => {
  const maxHits = data.length > 0 ? Math.max(...data.map((d) => d.blockedHits)) : 1;

  const getThreatBadge = (category: string) => {
    switch (category) {
      case 'DDOS_FLOOD':
        return <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold">SYN FLOOD</span>;
      case 'BRUTE_FORCE':
        return <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold">BRUTE FORCE</span>;
      case 'EXPLOIT_PROBE':
        return <span className="px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-bold">EXPLOIT</span>;
      case 'PORT_SCAN':
        return <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px] font-bold">PORT SCAN</span>;
      default:
        return <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">UNAUTHORIZED</span>;
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-rose-400" />
          <h3 className="text-sm font-bold text-white tracking-wide">
            Top Denied Threat Sources
          </h3>
        </div>
        <span className="text-[11px] text-slate-400">Ranked by Block Rate</span>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2.5 max-h-[300px] pr-1">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-500 text-xs font-mono py-8">
            No blocked threat sources detected yet.
          </div>
        ) : (
          data.map((item, idx) => {
            const percentage = (item.blockedHits / maxHits) * 100;
            return (
              <div
                key={item.ip}
                className="group relative bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800/80 hover:border-rose-900/60 rounded-lg p-2.5 transition-all"
              >
                {/* Visual Progress Bar */}
                <div
                  className="absolute inset-0 bg-rose-950/20 rounded-lg pointer-events-none transition-all"
                  style={{ width: `${percentage}%` }}
                />

                <div className="relative z-10 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-start sm:items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-500 w-4">
                      #{idx + 1}
                    </span>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span 
                          onClick={() => onSelectIp?.(item.ip)}
                          className="font-mono text-xs font-bold text-white hover:text-cyan-400 cursor-pointer"
                        >
                          {item.ip}
                        </span>
                        <span className="text-xs" title={item.countryName}>
                          {item.country}
                        </span>
                        {getThreatBadge(item.threatCategory)}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate max-w-[220px]">
                        {item.asn}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between sm:justify-end gap-3">
                    <div className="text-right">
                      <div className="font-mono text-xs font-bold text-rose-400">
                        {item.blockedHits.toLocaleString()} <span className="text-[10px] text-slate-400 font-normal">drops</span>
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        Target: {getPortServiceName(item.topPort)}
                      </div>
                    </div>

                    {/* Quick Actions */}
                    <div className="flex items-center gap-1 opacity-80 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => onSelectIp?.(item.ip)}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs"
                        title="Filter logs by this IP"
                      >
                        <Filter className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => onAnalyzeIp?.(item.ip, item)}
                        className="p-1 rounded bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 hover:text-cyan-100 border border-cyan-800/60 text-xs"
                        title="Ask Gemini AI to triage this IP"
                      >
                        <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
                      </button>
                      <button
                        onClick={() => onGenerateRule?.(item.ip)}
                        className="p-1 rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 hover:text-rose-100 border border-rose-800/60 text-xs"
                        title="Generate blocking firewall rule"
                      >
                        <ShieldBan className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
