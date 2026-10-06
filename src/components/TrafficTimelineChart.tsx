import React, { useState } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from 'recharts';
import { TimelineDataPoint } from '../types';
import { Activity, ShieldCheck, ShieldAlert, Zap, Clock } from 'lucide-react';

interface TrafficTimelineChartProps {
  data: TimelineDataPoint[];
  timeRange: 'all' | '15m' | '1h' | '6h' | '24h';
  onChangeTimeRange: (range: 'all' | '15m' | '1h' | '6h' | '24h') => void;
}

export const TrafficTimelineChart: React.FC<TrafficTimelineChartProps> = ({
  data,
  timeRange,
  onChangeTimeRange,
}) => {
  const [metricMode, setMetricMode] = useState<'events' | 'bandwidth'>('events');

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl text-xs font-mono">
          <div className="text-slate-300 font-semibold mb-2 border-b border-slate-800 pb-1 flex items-center gap-1.5">
            <Clock className="w-3 h-3 text-cyan-400" />
            <span>{label}</span>
          </div>
          {payload.map((entry: any, index: number) => (
            <div key={`tooltip-${index}`} className="flex items-center justify-between gap-4 py-0.5">
              <span className="flex items-center gap-1.5" style={{ color: entry.color }}>
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
                <span>{entry.name}:</span>
              </span>
              <span className="font-bold text-white">
                {metricMode === 'events'
                  ? entry.value.toLocaleString() + ' logs'
                  : (entry.value / 1024).toFixed(1) + ' KB'}
              </span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col h-full">
      {/* Header Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white tracking-wide">
              Network Traffic & Policy Enforcement Timeline
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time event frequency of Authorized (Allow) vs Denied (Drop/Block) packets
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Mode Switcher: Events vs Bandwidth */}
          <div className="flex items-center rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
            <button
              id="btn-timeline-events"
              onClick={() => setMetricMode('events')}
              className={`px-2.5 py-1 rounded-md transition-all font-medium ${
                metricMode === 'events'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Event Count
            </button>
            <button
              id="btn-timeline-bandwidth"
              onClick={() => setMetricMode('bandwidth')}
              className={`px-2.5 py-1 rounded-md transition-all font-medium ${
                metricMode === 'bandwidth'
                  ? 'bg-cyan-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Bandwidth (KB)
            </button>
          </div>

          {/* Time Range Selector */}
          <div className="flex items-center rounded-lg bg-slate-950 border border-slate-800 p-0.5 text-xs">
            {(['15m', '1h', '6h', '24h', 'all'] as const).map((r) => (
              <button
                key={r}
                id={`btn-timerange-${r}`}
                onClick={() => onChangeTimeRange(r)}
                className={`px-2 py-1 rounded-md uppercase font-medium transition-all ${
                  timeRange === r
                    ? 'bg-slate-800 text-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Chart Canvas */}
      <div className="flex-1 w-full min-h-[260px]">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-500 text-xs font-mono">
            Waiting for firewall log timeline events...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.6} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorDropped" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              
              <XAxis
                dataKey="timeLabel"
                stroke="#64748b"
                tick={{ fill: '#64748b', fontSize: 10 }}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
              />
              
              <YAxis
                stroke="#64748b"
                tick={{ fill: '#64748b', fontSize: 10 }}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
                tickFormatter={(val) => (val >= 1000 ? `${(val / 1000).toFixed(1)}k` : val)}
              />

              <Tooltip content={<CustomTooltip />} />

              <Legend
                wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                formatter={(value) => <span className="text-slate-300 font-medium">{value}</span>}
              />

              {metricMode === 'events' ? (
                <>
                  <Area
                    type="monotone"
                    dataKey="allowed"
                    name="Allowed Traffic"
                    stroke="#10b981"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorAllowed)"
                    stackId="1"
                  />
                  <Area
                    type="monotone"
                    dataKey="dropped"
                    name="Dropped Packets"
                    stroke="#f59e0b"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorDropped)"
                    stackId="1"
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked Ingress"
                    stroke="#f43f5e"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorBlocked)"
                    stackId="1"
                  />
                </>
              ) : (
                <Area
                  type="monotone"
                  dataKey="bytes"
                  name="Transit Bandwidth"
                  stroke="#38bdf8"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorAllowed)"
                />
              )}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};
