import React from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from 'recharts';
import { ProtocolStat } from '../types';
import { Layers } from 'lucide-react';

interface ProtocolDonutChartProps {
  data: ProtocolStat[];
  onSelectProtocol?: (protocol: string) => void;
}

const COLORS = ['#06b6d4', '#3b82f6', '#a855f7', '#ec4899', '#f97316', '#64748b'];

export const ProtocolDonutChart: React.FC<ProtocolDonutChartProps> = ({
  data,
  onSelectProtocol,
}) => {
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      return (
        <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg shadow-xl text-xs font-mono">
          <div className="text-white font-bold mb-1 flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color || COLORS[0] }} />
            <span>{item.protocol}</span>
          </div>
          <div className="text-slate-300">
            Events: <span className="font-semibold text-white">{item.count.toLocaleString()}</span>
          </div>
          <div className="text-slate-400">
            Share: <span className="font-semibold text-cyan-400">{item.percentage.toFixed(1)}%</span>
          </div>
          <div className="text-slate-400">
            Volume: <span className="font-semibold text-slate-200">{(item.bytes / 1024).toFixed(0)} KB</span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-bold text-white tracking-wide">
            Protocol Breakdown
          </h3>
        </div>
        <span className="text-[11px] text-slate-400">Layer 4 Ingress</span>
      </div>

      <div className="flex-1 flex flex-col sm:flex-row items-center justify-center min-h-[190px]">
        {/* Pie graphic */}
        <div className="w-full sm:w-1/2 h-[170px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                innerRadius={46}
                outerRadius={68}
                paddingAngle={3}
                dataKey="count"
                nameKey="protocol"
                onClick={(entry: any) => onSelectProtocol?.(entry?.payload?.protocol || entry?.protocol || entry?.name)}
                cursor="pointer"
              >
                {data.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.color || COLORS[index % COLORS.length]}
                    stroke="#0f172a"
                    strokeWidth={2}
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Legend pills with click to filter */}
        <div className="w-full sm:w-1/2 flex flex-col gap-1.5 pl-0 sm:pl-2">
          {data.map((item, index) => (
            <div
              key={item.protocol}
              onClick={() => onSelectProtocol?.(item.protocol)}
              className="flex items-center justify-between text-xs px-2 py-1 rounded bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800/60 cursor-pointer transition-colors"
            >
              <div className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: item.color || COLORS[index % COLORS.length] }}
                />
                <span className="font-bold text-slate-200">{item.protocol}</span>
              </div>
              <div className="flex items-center gap-2 font-mono">
                <span className="text-slate-400">{item.count}</span>
                <span className="text-cyan-400 font-semibold text-[11px]">
                  {item.percentage.toFixed(0)}%
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
