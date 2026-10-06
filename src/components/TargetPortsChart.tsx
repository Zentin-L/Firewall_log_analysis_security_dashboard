import React from 'react';
import { TargetPortStat } from '../types';
import { Network, Server } from 'lucide-react';

interface TargetPortsChartProps {
  data: TargetPortStat[];
  onSelectPort?: (port: number) => void;
}

export const TargetPortsChart: React.FC<TargetPortsChartProps> = ({
  data,
  onSelectPort,
}) => {
  const maxEvents = data.length > 0 ? Math.max(...data.map((d) => d.count)) : 1;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white tracking-wide">
            Target Service & Port Exposure
          </h3>
        </div>
        <span className="text-[11px] text-slate-400">Destination Ingress</span>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 max-h-[300px] pr-1">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-500 text-xs font-mono py-8">
            No port traffic telemetry available.
          </div>
        ) : (
          data.map((item) => {
            const allowCount = item.count - item.blockedCount;
            const blockRatio = item.count > 0 ? (item.blockedCount / item.count) * 100 : 0;
            const allowRatio = item.count > 0 ? (allowCount / item.count) * 100 : 0;
            const totalBarWidth = (item.count / maxEvents) * 100;

            return (
              <div
                key={item.port}
                onClick={() => onSelectPort?.(item.port)}
                className="group bg-slate-950/60 hover:bg-slate-800/70 border border-slate-800/60 hover:border-cyan-800/60 rounded-lg p-2.5 cursor-pointer transition-all"
              >
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-900/50 text-[11px]">
                      :{item.port}
                    </span>
                    <span className="font-semibold text-slate-200">{item.service}</span>
                  </div>
                  <div className="font-mono text-slate-400 text-[11px]">
                    <span className="text-white font-bold">{item.count.toLocaleString()}</span> logs
                    {item.blockedCount > 0 && (
                      <span className="text-rose-400 ml-1.5 font-semibold">
                        ({blockRatio.toFixed(0)}% blocked)
                      </span>
                    )}
                  </div>
                </div>

                {/* Stacked Bar (Green Allow vs Red Block) */}
                <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden flex">
                  <div
                    className="h-full bg-emerald-500 transition-all"
                    style={{ width: `${(allowCount / maxEvents) * 100}%` }}
                    title={`Allowed: ${allowCount}`}
                  />
                  <div
                    className="h-full bg-rose-500 transition-all"
                    style={{ width: `${(item.blockedCount / maxEvents) * 100}%` }}
                    title={`Blocked/Dropped: ${item.blockedCount}`}
                  />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
