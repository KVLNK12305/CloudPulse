import React, { useId } from 'react';

export interface ScaleTick {
  value: number;
  label: string;
}

interface InstrumentGaugeProps {
  title: string;
  value: number;
  minValue?: number;
  maxValue: number;
  displayValue: string;
  unit: string;
  sublabel: string;
  scaleTicks: ScaleTick[];
  dangerThreshold: number;
  statusLabel: string;
  statusColor?: string;
  comparisonText?: string;
}

export const InstrumentGauge: React.FC<InstrumentGaugeProps> = ({
  title,
  value,
  minValue = 0,
  maxValue,
  displayValue,
  unit,
  sublabel,
  scaleTicks,
  dangerThreshold,
  statusLabel,
  statusColor = '#38bdf8',
  comparisonText,
}) => {
  const uniqueId = useId().replace(/:/g, '');

  // Clamp fraction between 0.0 and 1.0
  const range = maxValue - minValue;
  const fraction = Math.max(0, Math.min(1, (value - minValue) / (range || 1)));

  // Automotive / Glass-Cockpit dial sweep: 270 degrees total sweep (-135deg to +135deg)
  const START_ANGLE = -135;
  const END_ANGLE = 135;
  const TOTAL_SWEEP = END_ANGLE - START_ANGLE; // 270 degrees

  // Active needle angle
  const needleAngle = START_ANGLE + fraction * TOTAL_SWEEP;

  // Danger threshold angle
  const dangerFraction = Math.max(0, Math.min(1, (dangerThreshold - minValue) / (range || 1)));
  const dangerAngle = START_ANGLE + dangerFraction * TOTAL_SWEEP;

  // Geometric coordinates (Center at 170, 152 in 340x280 viewBox)
  const cx = 170;
  const cy = 152;
  const outerBezelRadius = 136;
  const trackRadius = 124;
  const majorTickLength = 10;
  const minorTickLength = 5;
  const numbersRadius = 96;
  const hubRadius = 62;

  // Polar to Cartesian conversion helper
  const polarToCartesian = (radius: number, angleDeg: number) => {
    const rad = ((angleDeg - 90) * Math.PI) / 180;
    return {
      x: cx + radius * Math.cos(rad),
      y: cy + radius * Math.sin(rad),
    };
  };

  // SVG circular arc path generator
  const describeArc = (radius: number, startAngle: number, endAngle: number) => {
    const start = polarToCartesian(radius, startAngle);
    const end = polarToCartesian(radius, endAngle);
    const largeArcFlag = endAngle - startAngle <= 180 ? '0' : '1';
    return `M ${start.x} ${start.y} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${end.x} ${end.y}`;
  };

  // 1. Generate Synchronized Scale Ticks:
  // Major ticks aligned with scale numbers, minor ticks evenly dividing each interval
  interface DialTick {
    id: string;
    x1: number;
    y1: number;
    x2: number;
    y2: number;
    isMajor: boolean;
    isLit: boolean;
    isDanger: boolean;
  }

  const generatedTicks: DialTick[] = [];
  const sortedTicks = [...scaleTicks].sort((a, b) => a.value - b.value);

  // Generate ticks based on scale intervals
  if (sortedTicks.length > 1) {
    for (let i = 0; i < sortedTicks.length; i++) {
      const currentTick = sortedTicks[i];
      const curFraction = Math.max(0, Math.min(1, (currentTick.value - minValue) / (range || 1)));
      const curAngle = START_ANGLE + curFraction * TOTAL_SWEEP;

      const majorOuter = polarToCartesian(trackRadius, curAngle);
      const majorInner = polarToCartesian(trackRadius - majorTickLength, curAngle);

      generatedTicks.push({
        id: `major-${i}`,
        x1: majorInner.x,
        y1: majorInner.y,
        x2: majorOuter.x,
        y2: majorOuter.y,
        isMajor: true,
        isLit: currentTick.value <= value,
        isDanger: currentTick.value >= dangerThreshold,
      });

      // Minor ticks between consecutive major ticks (4 subdivisions = 5 segments)
      if (i < sortedTicks.length - 1) {
        const nextTick = sortedTicks[i + 1];
        const nextFraction = Math.max(0, Math.min(1, (nextTick.value - minValue) / (range || 1)));
        const minorSubdivisions = 4;

        for (let s = 1; s <= minorSubdivisions; s++) {
          const subFraction = curFraction + (s / (minorSubdivisions + 1)) * (nextFraction - curFraction);
          const subVal = minValue + subFraction * range;
          const subAngle = START_ANGLE + subFraction * TOTAL_SWEEP;

          const minorOuter = polarToCartesian(trackRadius, subAngle);
          const minorInner = polarToCartesian(trackRadius - minorTickLength, subAngle);

          generatedTicks.push({
            id: `minor-${i}-${s}`,
            x1: minorInner.x,
            y1: minorInner.y,
            x2: minorOuter.x,
            y2: minorOuter.y,
            isMajor: false,
            isLit: subVal <= value,
            isDanger: subVal >= dangerThreshold,
          });
        }
      }
    }
  }

  // 2. Scale Numbers along perimeter (sitting at radius 96, 18px inward from tick tips)
  const renderedNumbers = sortedTicks.map((tick, idx) => {
    const tFraction = Math.max(0, Math.min(1, (tick.value - minValue) / (range || 1)));
    const angle = START_ANGLE + tFraction * TOTAL_SWEEP;
    const pos = polarToCartesian(numbersRadius, angle);
    const isLit = tick.value <= value;
    const isDanger = tick.value >= dangerThreshold;

    return {
      id: idx,
      label: tick.label,
      x: pos.x,
      y: pos.y,
      isLit,
      isDanger,
    };
  });

  // 3. Crisp Track Arc (follows the exact circular path from start to current needle)
  const activeTrackArc = describeArc(trackRadius, START_ANGLE, Math.max(START_ANGLE + 1, needleAngle));

  // 4. Redline Danger Arc (from danger threshold to end of scale)
  const redlineArc = describeArc(trackRadius, dangerAngle, END_ANGLE);

  // 5. Needle Coordinates (from hub edge to outer track tip)
  const needleStart = polarToCartesian(hubRadius - 6, needleAngle);
  const needleEnd = polarToCartesian(trackRadius + 3, needleAngle);
  const needleTail = polarToCartesian(14, needleAngle + 180);

  return (
    <div
      className="speedo-instrument-card"
      style={{
        background: 'linear-gradient(155deg, #090e17 0%, #03060a 100%)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 'var(--radius-md)',
        padding: '16px 18px 14px',
        boxShadow: '0 10px 30px rgba(0, 0, 0, 0.7), inset 0 1px 0 rgba(255, 255, 255, 0.07)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Executive Header Row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          width: '100%',
          marginBottom: '2px',
          zIndex: 2,
        }}
      >
        <span
          style={{
            fontSize: '0.68rem',
            textTransform: 'uppercase',
            fontWeight: 800,
            letterSpacing: '0.08em',
            color: 'var(--text-tertiary)',
          }}
        >
          {title}
        </span>
        <span
          style={{
            fontSize: '0.60rem',
            fontFamily: 'var(--font-mono)',
            padding: '2px 8px',
            borderRadius: 'var(--radius-xs)',
            background: `${statusColor}18`,
            color: statusColor,
            border: `1px solid ${statusColor}35`,
            fontWeight: 700,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
          }}
        >
          {statusLabel}
        </span>
      </div>

      {/* Speedometer Instrument Dial */}
      <div
        className="speedo-face-container"
        style={{
          position: 'relative',
          width: '100%',
          maxWidth: '340px',
          height: '260px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <svg
          viewBox="0 0 340 280"
          style={{
            width: '100%',
            height: '100%',
            overflow: 'visible',
          }}
        >
          <defs>
            {/* 3D Machined Hub Bevel Gradient */}
            <radialGradient id={`hub-grad-${uniqueId}`} cx="45%" cy="35%" r="55%">
              <stop offset="0%" stopColor="#223044" />
              <stop offset="35%" stopColor="#121a28" />
              <stop offset="80%" stopColor="#080e18" />
              <stop offset="100%" stopColor="#020509" />
            </radialGradient>

            {/* Inset Deep OLED Display Face Gradient */}
            <radialGradient id={`oled-grad-${uniqueId}`} cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#060b13" />
              <stop offset="85%" stopColor="#020408" />
              <stop offset="100%" stopColor="#000000" />
            </radialGradient>
          </defs>

          {/* Recessed Subtle Outer Chassis Track */}
          <circle
            cx={cx}
            cy={cy}
            r={outerBezelRadius}
            fill="none"
            stroke="rgba(255, 255, 255, 0.03)"
            strokeWidth="1"
          />

          {/* Full Sweep Background Track Guide */}
          <path
            d={describeArc(trackRadius, START_ANGLE, END_ANGLE)}
            fill="none"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="1.8"
            strokeLinecap="round"
          />

          {/* Active Electric Cyan Arc (Crisp Arc with Smooth Drop Shadow, Zero Rectangle Clipping) */}
          <path
            d={activeTrackArc}
            fill="none"
            stroke="#38bdf8"
            strokeWidth="3"
            strokeLinecap="round"
            style={{
              filter: 'drop-shadow(0 0 6px rgba(56, 189, 248, 0.75))',
              transition: 'd 0.5s cubic-bezier(0.22, 1, 0.36, 1)',
            }}
          />

          {/* Redline Danger Zone Arc */}
          <path
            d={redlineArc}
            fill="none"
            stroke="#ef4444"
            strokeWidth="3.2"
            strokeLinecap="round"
            style={{
              filter: 'drop-shadow(0 0 6px rgba(239, 68, 68, 0.75))',
            }}
          />

          {/* Synchronized Perimeter Ticks (Major & Minor) */}
          {generatedTicks.map(t => (
            <line
              key={t.id}
              x1={t.x1}
              y1={t.y1}
              x2={t.x2}
              y2={t.y2}
              stroke={
                t.isDanger
                  ? t.isLit
                    ? '#f87171'
                    : 'rgba(239, 68, 68, 0.40)'
                  : t.isLit
                  ? '#93c5fd'
                  : 'rgba(255, 255, 255, 0.16)'
              }
              strokeWidth={t.isMajor ? 1.8 : 1}
              strokeLinecap="round"
              opacity={t.isLit ? 1 : 0.45}
            />
          ))}

          {/* Calibrated Perimeter Scale Numbers */}
          {renderedNumbers.map(s => (
            <text
              key={s.id}
              x={s.x}
              y={s.y}
              textAnchor="middle"
              dominantBaseline="central"
              fontSize="10"
              fontWeight={s.isLit ? '700' : '500'}
              fontFamily="var(--font-mono)"
              fill={
                s.isDanger
                  ? s.isLit
                    ? '#fca5a5'
                    : 'rgba(239, 68, 68, 0.55)'
                  : s.isLit
                  ? '#ffffff'
                  : 'rgba(255, 255, 255, 0.42)'
              }
              style={{
                textShadow: s.isLit
                  ? s.isDanger
                    ? '0 0 10px rgba(239, 68, 68, 0.8), 0 0 2px #ffffff'
                    : '0 0 8px rgba(56, 189, 248, 0.8), 0 0 2px #ffffff'
                  : 'none',
                transition: 'fill 0.3s ease, text-shadow 0.3s ease',
              }}
            >
              {s.label}
            </text>
          ))}

          {/* Needle Counterbalance Tail */}
          <line
            x1={cx}
            y1={cy}
            x2={needleTail.x}
            y2={needleTail.y}
            stroke="#475569"
            strokeWidth="1.6"
            strokeLinecap="round"
            style={{
              transition:
                'x2 0.7s cubic-bezier(0.34, 1.45, 0.64, 1), y2 0.7s cubic-bezier(0.34, 1.45, 0.64, 1)',
            }}
          />

          {/* Razor-Thin Illuminated White Needle */}
          <line
            x1={needleStart.x}
            y1={needleStart.y}
            x2={needleEnd.x}
            y2={needleEnd.y}
            stroke="#ffffff"
            strokeWidth="2"
            strokeLinecap="round"
            style={{
              filter: 'drop-shadow(0 0 3px rgba(255, 255, 255, 0.9))',
              transition:
                'x1 0.7s cubic-bezier(0.34, 1.45, 0.64, 1), y1 0.7s cubic-bezier(0.34, 1.45, 0.64, 1), x2 0.7s cubic-bezier(0.34, 1.45, 0.64, 1), y2 0.7s cubic-bezier(0.34, 1.45, 0.64, 1)',
            }}
          />

          {/* Needle Outer Specular Tip Bead */}
          <circle
            cx={needleEnd.x}
            cy={needleEnd.y}
            r="2"
            fill="#ffffff"
            style={{
              filter: 'drop-shadow(0 0 3px rgba(255, 255, 255, 0.9))',
              transition:
                'cx 0.7s cubic-bezier(0.34, 1.45, 0.64, 1), cy 0.7s cubic-bezier(0.34, 1.45, 0.64, 1)',
            }}
          />

          {/* ── 3D Multi-Stage Center Hub ── */}
          {/* Outer Bevel Cylinder with Specular Rim */}
          <circle
            cx={cx}
            cy={cy}
            r={hubRadius + 4}
            fill={`url(#hub-grad-${uniqueId})`}
            stroke="rgba(255, 255, 255, 0.16)"
            strokeWidth="1.5"
            style={{ filter: 'drop-shadow(0 6px 16px rgba(0,0,0,0.85))' }}
          />

          {/* Middle Metallic Ring */}
          <circle
            cx={cx}
            cy={cy}
            r={hubRadius - 2}
            fill="none"
            stroke="rgba(255, 255, 255, 0.22)"
            strokeWidth="1.2"
          />

          {/* Deep Inset OLED Display Face */}
          <circle
            cx={cx}
            cy={cy}
            r={hubRadius - 8}
            fill={`url(#oled-grad-${uniqueId})`}
            stroke="#080e18"
            strokeWidth="1"
          />
        </svg>

        {/* Center Digital Telemetry Overlay (Clean OLED Hub Without Screw Overlap) */}
        <div
          style={{
            position: 'absolute',
            left: '50%',
            top: '54.3%',
            transform: 'translate(-50%, -50%)',
            width: '98px',
            height: '98px',
            borderRadius: '50%',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            pointerEvents: 'none',
            textAlign: 'center',
          }}
        >
          {/* Unit / Metric Category */}
          <span
            style={{
              fontSize: '0.58rem',
              color: 'var(--text-tertiary)',
              textTransform: 'uppercase',
              fontWeight: 700,
              letterSpacing: '0.08em',
              lineHeight: 1,
              marginBottom: '3px',
            }}
          >
            {unit}
          </span>

          {/* Primary Numeric Readout */}
          <span
            style={{
              fontSize: displayValue.length > 5 ? '1.24rem' : '1.50rem',
              fontWeight: 900,
              fontFamily: 'var(--font-mono)',
              color: '#ffffff',
              letterSpacing: '-0.03em',
              lineHeight: 1.1,
              textShadow: '0 0 14px rgba(56, 189, 248, 0.45), 0 0 2px #ffffff',
            }}
          >
            {displayValue}
          </span>

          {/* Micro Status Dot */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginTop: '3px' }}>
            <span
              style={{
                width: '5px',
                height: '5px',
                borderRadius: '50%',
                backgroundColor: statusColor,
                boxShadow: `0 0 5px ${statusColor}`,
              }}
            />
            <span
              style={{
                fontSize: '0.55rem',
                color: statusColor,
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
              }}
            >
              {statusLabel.split(' ')[0]}
            </span>
          </div>
        </div>
      </div>

      {/* Subtitle / Context Comparison Footnote */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          width: '100%',
          marginTop: '-4px',
          paddingTop: '8px',
          borderTop: '1px solid rgba(255, 255, 255, 0.06)',
          zIndex: 2,
        }}
      >
        <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
          {sublabel}
        </span>
        {comparisonText && (
          <span
            style={{
              fontSize: '0.66rem',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              color: 'var(--text-tertiary)',
            }}
          >
            {comparisonText}
          </span>
        )}
      </div>
    </div>
  );
};
