import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Play, 
  Pause, 
  UploadCloud, 
  Bot, 
  Download, 
  Trash2, 
  Sparkles,
  RefreshCw
} from 'lucide-react';
import { PRESET_DATASETS } from '../utils/sampleData';

interface HeaderProps {
  isStreaming: boolean;
  onToggleStreaming: () => void;
  streamSpeed: number;
  onChangeStreamSpeed: (speed: number) => void;
  onOpenConnector: () => void;
  onOpenCopilot: () => void;
  onSelectPreset: (presetKey: string) => void;
  onExportLogs: (format: 'csv' | 'json') => void;
  onClearLogs: () => void;
  totalLogsCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  isStreaming,
  onToggleStreaming,
  streamSpeed,
  onChangeStreamSpeed,
  onOpenConnector,
  onOpenCopilot,
  onSelectPreset,
  onExportLogs,
  onClearLogs,
  totalLogsCount,
}) => {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md px-4 lg:px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        {/* Brand & SOC Status */}
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                NetSentinel
                <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  SOC v3.2
                </span>
              </h1>
              {/* Real-time Status Beacon */}
              <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
                <span className={`h-2 w-2 rounded-full ${isStreaming ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
                <span>{isStreaming ? 'STREAMING ACTIVE' : 'INGESTION PAUSED'}</span>
              </div>
            </div>
            <p className="text-xs text-slate-400">
              Firewall Telemetry Analytics, Threat Detection & AI Triage
            </p>
          </div>
        </div>

        {/* Controls & Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {/* Live Ingestion Toggle */}
          <div className="flex items-center rounded-lg bg-slate-900 border border-slate-800 p-1">
            <button
              id="btn-toggle-stream"
              onClick={onToggleStreaming}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-semibold transition-all ${
                isStreaming
                  ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
              title={isStreaming ? 'Pause live packet stream' : 'Resume live packet stream'}
            >
              {isStreaming ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  <span>Pause</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Stream</span>
                </>
              )}
            </button>

            {/* Speed Selector */}
            {isStreaming && (
              <select
                id="select-stream-speed"
                value={streamSpeed}
                onChange={(e) => onChangeStreamSpeed(Number(e.target.value))}
                className="bg-transparent text-xs text-slate-300 px-2 py-1 focus:outline-none cursor-pointer border-l border-slate-800 ml-1"
              >
                <option value={1000} className="bg-slate-900">1 event/s</option>
                <option value={500} className="bg-slate-900">2 events/s</option>
                <option value={200} className="bg-slate-900">5 events/s (Burst)</option>
                <option value={2500} className="bg-slate-900">0.4 event/s</option>
              </select>
            )}
          </div>

          {/* Scenario Preset Selector */}
          <select
            id="select-preset-scenario"
            onChange={(e) => {
              if (e.target.value) {
                onSelectPreset(e.target.value);
              }
            }}
            defaultValue=""
            className="bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs text-slate-200 rounded-lg px-2.5 py-2 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
          >
            <option value="" disabled>Load Attack Scenario...</option>
            {Object.entries(PRESET_DATASETS).map(([key, item]) => (
              <option key={key} value={key} className="bg-slate-900">
                {item.name}
              </option>
            ))}
          </select>

          {/* Connect Logs / Ingest Modal */}
          <button
            id="btn-open-connector-modal"
            onClick={onOpenConnector}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-medium transition-colors"
          >
            <UploadCloud className="w-4 h-4 text-cyan-400" />
            <span>Connect Logs</span>
          </button>

          {/* AI SOC Copilot */}
          <button
            id="btn-open-ai-copilot"
            onClick={onOpenCopilot}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition-all cursor-pointer"
          >
            <Sparkles className="w-4 h-4 text-yellow-300" />
            <span>AI SOC Copilot</span>
          </button>

          {/* Export Dropdown */}
          <div className="relative group">
            <button
              id="btn-export-logs"
              className="flex items-center gap-1.5 px-2.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-medium transition-colors"
              title="Export Log Records"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export</span>
            </button>
            <div className="absolute right-0 mt-1 w-32 bg-slate-900 border border-slate-800 rounded-lg shadow-xl py-1 hidden group-hover:block z-50">
              <button
                id="btn-export-csv"
                onClick={() => onExportLogs('csv')}
                className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-cyan-400"
              >
                Export as CSV
              </button>
              <button
                id="btn-export-json"
                onClick={() => onExportLogs('json')}
                className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-cyan-400"
              >
                Export as JSON
              </button>
            </div>
          </div>

          {/* Clear Logs */}
          <button
            id="btn-clear-logs"
            onClick={onClearLogs}
            className="p-2 rounded-lg bg-slate-900 hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 border border-slate-800 hover:border-rose-900/60 text-xs transition-colors"
            title="Clear all logs from buffer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
