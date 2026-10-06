import React from 'react';
import { GeoThreatStat } from '../types';
import { Globe, MapPin, ShieldAlert, Crosshair } from 'lucide-react';
import { COUNTRY_MAP } from '../utils/geoData';

interface GeoThreatMapProps {
  data: GeoThreatStat[];
  onSelectCountry?: (countryCode: string) => void;
}

export const GeoThreatMap: React.FC<GeoThreatMapProps> = ({
  data,
  onSelectCountry,
}) => {
  // Simple 2D equirectangular projection to SVG coords (width 800, height 400)
  const projectCoords = (lat: number, lng: number) => {
    const x = ((lng + 180) / 360) * 800;
    const y = ((90 - lat) / 180) * 400;
    return { x, y };
  };

  const topCountries = [...data].sort((a, b) => b.blockedEvents - a.blockedEvents).slice(0, 6);

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white tracking-wide">
            Global Ingress Threat Map
          </h3>
        </div>
        <span className="text-[11px] text-slate-400">GeoIP Telemetry</span>
      </div>

      <div className="flex-1 flex flex-col lg:flex-row gap-4 items-center">
        {/* World Vector Visual Stage */}
        <div className="relative w-full lg:w-2/3 h-[220px] bg-slate-950/80 rounded-xl border border-slate-800/80 overflow-hidden flex items-center justify-center">
          {/* Subtle grid background */}
          <div 
            className="absolute inset-0 opacity-15"
            style={{
              backgroundImage: 'radial-gradient(#38bdf8 1px, transparent 1px), radial-gradient(#06b6d4 1px, transparent 1px)',
              backgroundSize: '20px 20px',
            }}
          />

          <svg viewBox="0 0 800 400" className="w-full h-full object-contain">
            {/* Equator & Meridians */}
            <line x1="0" y1="200" x2="800" y2="200" stroke="#1e293b" strokeDasharray="4 4" strokeWidth="1" />
            <line x1="400" y1="0" x2="400" y2="400" stroke="#1e293b" strokeDasharray="4 4" strokeWidth="1" />

            {/* Stylized continent silhouettes */}
            <g fill="#1e293b" opacity="0.7">
              {/* North America */}
              <path d="M120 70 Q 180 60, 240 90 T 260 180 T 180 230 T 120 180 Z" />
              {/* South America */}
              <path d="M220 230 Q 280 250, 270 330 T 220 370 T 190 280 Z" />
              {/* Europe */}
              <path d="M380 70 Q 450 60, 480 120 T 430 160 T 360 130 Z" />
              {/* Africa */}
              <path d="M380 170 Q 460 180, 460 270 T 410 330 T 360 250 Z" />
              {/* Asia */}
              <path d="M480 70 Q 650 60, 680 180 T 560 240 T 470 170 Z" />
              {/* Australia */}
              <path d="M620 270 Q 700 270, 710 330 T 630 350 Z" />
            </g>

            {/* Destination Target Data Center (e.g. US-East) */}
            <g transform={`translate(${projectCoords(37.5, -77.5).x}, ${projectCoords(37.5, -77.5).y})`}>
              <circle r="8" fill="#06b6d4" opacity="0.3" className="animate-ping" />
              <circle r="4" fill="#06b6d4" />
              <text x="8" y="4" fill="#38bdf8" fontSize="9" fontWeight="bold">Enterprise DMZ</text>
            </g>

            {/* Country Threat Nodes */}
            {data.map((item) => {
              const info = COUNTRY_MAP[item.countryCode];
              if (!info || item.countryCode === 'LOCAL') return null;
              const { x, y } = projectCoords(info.lat, info.lng);
              const isHighThreat = item.blockedEvents > 10;
              const targetCoords = projectCoords(37.5, -77.5);

              return (
                <g 
                  key={item.countryCode} 
                  className="cursor-pointer group"
                  onClick={() => onSelectCountry?.(item.countryCode)}
                >
                  {/* Attack vector arc */}
                  {item.blockedEvents > 0 && (
                    <path
                      d={`M ${x} ${y} Q ${(x + targetCoords.x) / 2} ${(y + targetCoords.y) / 2 - 30} ${targetCoords.x} ${targetCoords.y}`}
                      fill="none"
                      stroke={isHighThreat ? '#f43f5e' : '#f59e0b'}
                      strokeWidth="1"
                      strokeDasharray="3 3"
                      opacity="0.4"
                    />
                  )}

                  {/* Pulsing circle */}
                  <circle
                    cx={x}
                    cy={y}
                    r={Math.min(14, 4 + item.blockedEvents / 5)}
                    fill={isHighThreat ? '#f43f5e' : '#06b6d4'}
                    opacity="0.25"
                    className={isHighThreat ? 'animate-pulse' : ''}
                  />
                  <circle
                    cx={x}
                    cy={y}
                    r={Math.min(6, 2 + item.blockedEvents / 10)}
                    fill={isHighThreat ? '#f43f5e' : '#06b6d4'}
                  />
                  <text
                    cx={x}
                    cy={y - 8}
                    x={x}
                    y={y - 8}
                    textAnchor="middle"
                    fill="#94a3b8"
                    fontSize="9"
                    fontFamily="monospace"
                  >
                    {item.countryCode}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Top Origin Country Leaderboard */}
        <div className="w-full lg:w-1/3 flex flex-col gap-1.5">
          <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 flex items-center gap-1.5">
            <Crosshair className="w-3.5 h-3.5 text-rose-400" />
            <span>High-Volume Origins</span>
          </div>

          {topCountries.map((c) => {
            const countryInfo = COUNTRY_MAP[c.countryCode];
            return (
              <div
                key={c.countryCode}
                onClick={() => onSelectCountry?.(c.countryCode)}
                className="flex items-center justify-between p-2 rounded-lg bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800/60 cursor-pointer transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className="text-base">{countryInfo?.flag || '🌐'}</span>
                  <div>
                    <div className="text-xs font-bold text-white leading-tight">
                      {c.countryName}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">
                      {c.countryCode}
                    </div>
                  </div>
                </div>

                <div className="text-right font-mono">
                  <div className="text-xs font-bold text-rose-400">
                    {c.blockedEvents} <span className="text-[10px] text-slate-400 font-normal">drops</span>
                  </div>
                  <div className="text-[10px] text-slate-400">
                    {c.totalEvents} total
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
