import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Flame, 
  Globe, 
  Activity, 
  Zap, 
  ArrowUpRight, 
  Server,
  Lock
} from 'lucide-react';
import { DashboardStats } from '../types';

interface KPICardsProps {
  stats: DashboardStats;
  onFilterByStatus?: (action: string) => void;
  onFilterByThreats?: () => void;
}

export const KPICards: React.FC<KPICardsProps> = ({
  stats,
  onFilterByStatus,
  onFilterByThreats,
}) => {
  const formatBytes = (bytes: number) => {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(0) + ' KB';
    return bytes + ' B';
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
      {/* 1. Total Events */}
      <div 
        id="kpi-total-logs"
        className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-3.5 hover:border-slate-700 transition-all flex flex-col justify-between"
      >
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider">Total Logs</span>
          <Activity className="w-4 h-4 text-cyan-400" />
        </div>
        <div>
          <div className="text-2xl font-bold text-white font-mono">
            {stats.totalLogs.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-cyan-400 font-semibold">{stats.totalPackets}</span> pkts processed
          </div>
        </div>
      </div>

      {/* 2. Block / Deny Rate */}
      <div 
        id="kpi-block-rate"
        onClick={() => onFilterByStatus?.('DROP')}
        className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-3.5 hover:border-rose-800/50 transition-all cursor-pointer group flex flex-col justify-between"
      >
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider">Block Rate</span>
          <ShieldAlert className="w-4 h-4 text-rose-400 group-hover:scale-110 transition-transform" />
        </div>
        <div>
          <div className="text-2xl font-bold text-rose-400 font-mono flex items-baseline gap-1">
            {stats.blockRate.toFixed(1)}%
            <span className="text-xs font-normal text-slate-400">drop</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            <span className="text-rose-400 font-semibold font-mono">{stats.blockedCount + stats.droppedCount}</span> denied events
          </div>
        </div>
      </div>

      {/* 3. Allowed Traffic */}
      <div 
        id="kpi-allowed-traffic"
        onClick={() => onFilterByStatus?.('ALLOW')}
        className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-3.5 hover:border-emerald-800/50 transition-all cursor-pointer group flex flex-col justify-between"
      >
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider">Allowed Ingress</span>
          <ShieldCheck className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition-transform" />
        </div>
        <div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">
            {stats.allowedCount.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            <span className="text-emerald-400 font-semibold font-mono">
              {stats.totalLogs > 0 ? ((stats.allowedCount / stats.totalLogs) * 100).toFixed(1) : 0}%
            </span> authorized
          </div>
        </div>
      </div>

      {/* 4. Active Correlated Incidents */}
      <div 
        id="kpi-threat-alerts"
        onClick={onFilterByThreats}
        className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-3.5 hover:border-amber-800/50 transition-all cursor-pointer group flex flex-col justify-between"
      >
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider">Threat Alerts</span>
          <Flame className="w-4 h-4 text-amber-400 group-hover:scale-110 transition-transform" />
        </div>
        <div>
          <div className="text-2xl font-bold text-amber-400 font-mono flex items-center gap-1.5">
            {stats.activeThreatCount}
            {stats.criticalThreatCount > 0 && (
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/70 animate-pulse">
                {stats.criticalThreatCount} CRIT
              </span>
            )}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Correlated attacks detected
          </div>
        </div>
      </div>

      {/* 5. Unique Threat Source IPs */}
      <div 
        id="kpi-unique-ips"
        className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-3.5 hover:border-slate-700 transition-all flex flex-col justify-between"
      >
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider">Source IPs</span>
          <Globe className="w-4 h-4 text-purple-400" />
        </div>
        <div>
          <div className="text-2xl font-bold text-purple-400 font-mono">
            {stats.uniqueSourceIps}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Targeting <span className="text-slate-200 font-semibold">{stats.uniqueDestIps}</span> internal nodes
          </div>
        </div>
      </div>

      {/* 6. Bandwidth Volume */}
      <div 
        id="kpi-bandwidth"
        className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-3.5 hover:border-slate-700 transition-all flex flex-col justify-between"
      >
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider">Bandwidth</span>
          <Zap className="w-4 h-4 text-blue-400" />
        </div>
        <div>
          <div className="text-2xl font-bold text-blue-400 font-mono">
            {formatBytes(stats.totalBytes)}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Total transit payload
          </div>
        </div>
      </div>
    </div>
  );
};
