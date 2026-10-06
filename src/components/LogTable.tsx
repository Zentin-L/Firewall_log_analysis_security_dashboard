import React, { useState, useMemo } from 'react';
import { FirewallLog, FilterState, LogSeverity, FirewallAction } from '../types';
import { 
  Search, 
  Filter, 
  ArrowRight, 
  Sparkles, 
  ShieldBan, 
  SlidersHorizontal, 
  X, 
  ChevronLeft, 
  ChevronRight,
  Eye,
  ArrowUpDown
} from 'lucide-react';
import { getPortServiceName } from '../utils/geoData';

interface LogTableProps {
  logs: FirewallLog[];
  filters: FilterState;
  onUpdateFilters: (filters: Partial<FilterState>) => void;
  onResetFilters: () => void;
  onSelectLog: (log: FirewallLog) => void;
  onAiTriageLog: (log: FirewallLog) => void;
  onGenerateRule: (ip: string) => void;
}

export const LogTable: React.FC<LogTableProps> = ({
  logs,
  filters,
  onUpdateFilters,
  onResetFilters,
  onSelectLog,
  onAiTriageLog,
  onGenerateRule,
}) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [sortField, setSortField] = useState<'timestamp' | 'bytes' | 'severity'>('timestamp');
  const [sortAsc, setSortAsc] = useState(false);

  // Filter logs
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      // Search query
      if (filters.searchQuery) {
        const query = filters.searchQuery.toLowerCase();
        const matches =
          log.sourceIp.toLowerCase().includes(query) ||
          log.destinationIp.toLowerCase().includes(query) ||
          String(log.destinationPort).includes(query) ||
          String(log.sourcePort).includes(query) ||
          log.ruleName.toLowerCase().includes(query) ||
          log.protocol.toLowerCase().includes(query) ||
          (log.sourceCountryName && log.sourceCountryName.toLowerCase().includes(query)) ||
          (log.sourceAsn && log.sourceAsn.toLowerCase().includes(query)) ||
          (log.threatDescription && log.threatDescription.toLowerCase().includes(query));
        if (!matches) return false;
      }

      // Action
      if (filters.action && filters.action !== 'all') {
        if (log.action !== filters.action) return false;
      }

      // Protocol
      if (filters.protocol && filters.protocol !== 'all') {
        if (log.protocol !== filters.protocol) return false;
      }

      // Severity
      if (filters.severity && filters.severity !== 'all') {
        if (log.severity !== filters.severity) return false;
      }

      // Threat Category
      if (filters.threatCategory && filters.threatCategory !== 'all') {
        if (filters.threatCategory === 'THREATS_ONLY') {
          if (log.threatCategory === 'BENIGN' && log.action === 'ALLOW') return false;
        } else if (log.threatCategory !== filters.threatCategory) {
          return false;
        }
      }

      // Country
      if (filters.country && filters.country !== 'all') {
        if (log.sourceCountry !== filters.country) return false;
      }

      // Selected IP
      if (filters.selectedIp) {
        if (log.sourceIp !== filters.selectedIp && log.destinationIp !== filters.selectedIp) return false;
      }

      // Selected Port
      if (filters.selectedPort) {
        if (log.destinationPort !== filters.selectedPort) return false;
      }

      return true;
    });
  }, [logs, filters]);

  // Sort logs
  const sortedLogs = useMemo(() => {
    const list = [...filteredLogs];
    const severityRank: Record<LogSeverity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

    list.sort((a, b) => {
      let diff = 0;
      if (sortField === 'timestamp') {
        diff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      } else if (sortField === 'bytes') {
        diff = b.bytes - a.bytes;
      } else if (sortField === 'severity') {
        diff = severityRank[b.severity] - severityRank[a.severity];
      }
      return sortAsc ? -diff : diff;
    });

    return list;
  }, [filteredLogs, sortField, sortAsc]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(sortedLogs.length / pageSize));
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedLogs.slice(start, start + pageSize);
  }, [sortedLogs, currentPage, pageSize]);

  const handleSort = (field: 'timestamp' | 'bytes' | 'severity') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const hasActiveFilters =
    Boolean(filters.searchQuery) ||
    (filters.action && filters.action !== 'all') ||
    (filters.protocol && filters.protocol !== 'all') ||
    (filters.severity && filters.severity !== 'all') ||
    (filters.threatCategory && filters.threatCategory !== 'all') ||
    Boolean(filters.selectedIp) ||
    Boolean(filters.selectedPort) ||
    (filters.country && filters.country !== 'all');

  const getActionBadge = (action: FirewallAction) => {
    switch (action) {
      case 'ALLOW':
        return (
          <span className="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold font-mono">
            ALLOW
          </span>
        );
      case 'DROP':
        return (
          <span className="px-2 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold font-mono">
            DROP
          </span>
        );
      case 'BLOCK':
        return (
          <span className="px-2 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold font-mono">
            BLOCK
          </span>
        );
      case 'REJECT':
        return (
          <span className="px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-bold font-mono">
            REJECT
          </span>
        );
    }
  };

  const getSeverityBadge = (severity: LogSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="text-[10px] font-bold text-rose-400">CRIT</span>;
      case 'HIGH':
        return <span className="text-[10px] font-bold text-amber-400">HIGH</span>;
      case 'MEDIUM':
        return <span className="text-[10px] font-semibold text-yellow-400">MED</span>;
      case 'LOW':
        return <span className="text-[10px] text-blue-400">LOW</span>;
      default:
        return <span className="text-[10px] text-slate-500">INFO</span>;
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col">
      {/* Header & Filter Controls Bar */}
      <div className="flex flex-col gap-3 mb-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              Ingested Firewall Telemetry Stream
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-cyan-400 font-mono">
                {sortedLogs.length.toLocaleString()} matching
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Decoded packet streams across edge firewalls, VPC flow logs, and perimeter ACLs
            </p>
          </div>

          {/* Active Filter Chips */}
          {hasActiveFilters && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-xs text-slate-400">Filters:</span>
              {filters.selectedIp && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 text-xs font-mono">
                  IP: {filters.selectedIp}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => onUpdateFilters({ selectedIp: undefined })} />
                </span>
              )}
              {filters.selectedPort && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 text-xs font-mono">
                  Port: {filters.selectedPort}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => onUpdateFilters({ selectedPort: undefined })} />
                </span>
              )}
              {filters.action !== 'all' && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-800 text-slate-200 text-xs">
                  Action: {filters.action}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => onUpdateFilters({ action: 'all' })} />
                </span>
              )}
              {filters.threatCategory !== 'all' && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800 text-xs">
                  {filters.threatCategory}
                  <X className="w-3 h-3 cursor-pointer" onClick={() => onUpdateFilters({ threatCategory: 'all' })} />
                </span>
              )}
              <button
                id="btn-reset-filters"
                onClick={onResetFilters}
                className="text-xs text-rose-400 hover:underline ml-1 font-semibold"
              >
                Clear all
              </button>
            </div>
          )}
        </div>

        {/* Filter Input Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {/* Search Input */}
          <div className="relative lg:col-span-2">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="input-log-search"
              type="text"
              placeholder="Search IP, Port, Rule, ASN, Country, Payload..."
              value={filters.searchQuery}
              onChange={(e) => {
                onUpdateFilters({ searchQuery: e.target.value });
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 hover:border-slate-700 focus:border-cyan-500 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none"
            />
          </div>

          {/* Action Filter */}
          <select
            id="select-filter-action"
            value={filters.action}
            onChange={(e) => {
              onUpdateFilters({ action: e.target.value });
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Verdicts</option>
            <option value="ALLOW">ALLOW Only</option>
            <option value="DROP">DROP / DENY</option>
            <option value="BLOCK">BLOCK Only</option>
          </select>

          {/* Protocol Filter */}
          <select
            id="select-filter-protocol"
            value={filters.protocol}
            onChange={(e) => {
              onUpdateFilters({ protocol: e.target.value });
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>

          {/* Threat Category Filter */}
          <select
            id="select-filter-threat"
            value={filters.threatCategory}
            onChange={(e) => {
              onUpdateFilters({ threatCategory: e.target.value });
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Categories</option>
            <option value="THREATS_ONLY">⚠️ Threats & Drops Only</option>
            <option value="PORT_SCAN">Port Scans</option>
            <option value="BRUTE_FORCE">Brute Force</option>
            <option value="DDOS_FLOOD">SYN Floods / DDoS</option>
            <option value="EXPLOIT_PROBE">Exploit Probes</option>
            <option value="BENIGN">Benign Authorized</option>
          </select>
        </div>
      </div>

      {/* Log Data Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3 cursor-pointer select-none" onClick={() => handleSort('timestamp')}>
                <div className="flex items-center gap-1">
                  <span>Timestamp</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-2.5 px-3">Verdict</th>
              <th className="py-2.5 px-3 cursor-pointer select-none" onClick={() => handleSort('severity')}>
                <div className="flex items-center gap-1">
                  <span>Sev</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-2.5 px-3">Source (Client)</th>
              <th className="py-2.5 px-2 text-center">Dir</th>
              <th className="py-2.5 px-3">Destination (Target)</th>
              <th className="py-2.5 px-3">Proto</th>
              <th className="py-2.5 px-3">Firewall Policy / Rule</th>
              <th className="py-2.5 px-3 cursor-pointer select-none" onClick={() => handleSort('bytes')}>
                <div className="flex items-center gap-1">
                  <span>Bytes</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-2.5 px-3 text-right">Actions</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800/60 font-mono">
            {paginatedLogs.length === 0 ? (
              <tr>
                <td colSpan={10} className="text-center py-10 text-slate-500 font-sans text-xs">
                  No firewall log events match the selected criteria.
                </td>
              </tr>
            ) : (
              paginatedLogs.map((log) => {
                const isDenied = log.action !== 'ALLOW';
                const timeStr = new Date(log.timestamp).toLocaleTimeString();

                return (
                  <tr
                    key={log.id}
                    className={`hover:bg-slate-800/50 transition-colors ${
                      isDenied ? 'bg-rose-950/5' : ''
                    }`}
                  >
                    {/* Timestamp */}
                    <td className="py-2 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                      {timeStr}
                    </td>

                    {/* Action */}
                    <td className="py-2 px-3 whitespace-nowrap">
                      {getActionBadge(log.action)}
                    </td>

                    {/* Severity */}
                    <td className="py-2 px-3 whitespace-nowrap">
                      {getSeverityBadge(log.severity)}
                    </td>

                    {/* Source IP */}
                    <td className="py-2 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs" title={log.sourceCountryName || ''}>
                          {log.sourceCountry === 'LOCAL' ? '🛡️' : log.sourceCountry || '🌐'}
                        </span>
                        <span 
                          onClick={() => onUpdateFilters({ selectedIp: log.sourceIp })}
                          className="font-bold text-slate-200 hover:text-cyan-400 cursor-pointer"
                        >
                          {log.sourceIp}
                        </span>
                        <span className="text-slate-500 text-[10px]">:{log.sourcePort}</span>
                      </div>
                    </td>

                    {/* Direction */}
                    <td className="py-2 px-2 text-center text-slate-600">
                      <ArrowRight className="w-3.5 h-3.5 inline text-slate-500" />
                    </td>

                    {/* Destination IP & Port */}
                    <td className="py-2 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-300">{log.destinationIp}</span>
                        <span 
                          onClick={() => onUpdateFilters({ selectedPort: log.destinationPort })}
                          className="text-cyan-400 font-bold hover:underline cursor-pointer"
                        >
                          :{log.destinationPort}
                        </span>
                        <span className="text-[10px] text-slate-500 font-sans">
                          ({getPortServiceName(log.destinationPort)})
                        </span>
                      </div>
                    </td>

                    {/* Protocol */}
                    <td className="py-2 px-3 text-slate-300 whitespace-nowrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-bold">
                        {log.protocol}
                      </span>
                    </td>

                    {/* Rule Name */}
                    <td className="py-2 px-3 text-slate-400 text-[11px] truncate max-w-[160px] whitespace-nowrap" title={log.ruleName}>
                      {log.ruleName}
                    </td>

                    {/* Bytes */}
                    <td className="py-2 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                      {log.bytes >= 1024 ? `${(log.bytes / 1024).toFixed(1)} KB` : `${log.bytes} B`}
                    </td>

                    {/* Action Buttons */}
                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5 font-sans">
                        <button
                          onClick={() => onSelectLog(log)}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white"
                          title="Inspect Packet Details"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onAiTriageLog(log)}
                          className="p-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 hover:text-cyan-100 border border-cyan-800"
                          title="Ask Gemini AI to Triage"
                        >
                          <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
                        </button>
                        {isDenied && (
                          <button
                            onClick={() => onGenerateRule(log.sourceIp)}
                            className="p-1 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 hover:text-rose-100 border border-rose-800"
                            title="Generate Blocking Rule"
                          >
                            <ShieldBan className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 mt-3 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <span>Rows per page:</span>
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 focus:outline-none"
          >
            <option value={15}>15</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
          <span className="font-mono">
            Showing {(currentPage - 1) * pageSize + 1} - {Math.min(currentPage * pageSize, sortedLogs.length)} of {sortedLogs.length}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="p-1.5 rounded bg-slate-950 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 disabled:pointer-events-none text-slate-300"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono px-2">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="p-1.5 rounded bg-slate-950 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 disabled:pointer-events-none text-slate-300"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
