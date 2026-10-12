import React from 'react';

interface SegmentedMeterProps {
  value: number; // 0 to 100
  totalBlocks?: number;
  colorScheme?: 'teal' | 'sky' | 'amber' | 'rose' | 'violet' | 'multi';
  variant?: 'blocks' | 'hazard-stripes' | 'cyber-ticks';
  showSpark?: boolean;
  height?: number;
  label?: string;
}

export const SegmentedMeter: React.FC<SegmentedMeterProps> = ({
  value,
  totalBlocks = 16,
  colorScheme = 'teal',
  variant = 'blocks',
  showSpark = true,
  height = 8,
  label,
}) => {
  const clamped = Math.max(0, Math.min(100, Math.round(value)));
  const filledBlocks = Math.round((clamped / 100) * totalBlocks);

  // Color resolver based on position or fixed scheme
  const getBlockColor = (index: number) => {
    if (colorScheme === 'multi') {
      const pct = (index / totalBlocks) * 100;
      if (pct > 80) return '#fc8181'; // Danger Rose
      if (pct > 60) return '#f6ad55'; // Warning Amber
      if (pct > 30) return '#63b3ed'; // Sky
      return '#38d9a9'; // Emerald
    }

    switch (colorScheme) {
      case 'sky':
        return '#63b3ed';
      case 'amber':
        return '#f6ad55';
      case 'rose':
        return '#fc8181';
      case 'violet':
        return '#9f7aea';
      case 'teal':
      default:
        return '#38d9a9';
    }
  };

  if (variant === 'hazard-stripes') {
    return (
      <div
        className="hazard-meter-container"
        style={{
          height: `${height}px`,
          background: 'rgba(255, 255, 255, 0.05)',
          borderRadius: 'var(--radius-xs)',
          overflow: 'hidden',
          position: 'relative',
          border: '1px solid rgba(255, 255, 255, 0.08)',
        }}
        title={label ? `${label}: ${clamped}%` : `${clamped}%`}
      >
        <div
          className="hazard-meter-fill"
          style={{
            width: `${clamped}%`,
            height: '100%',
            background: `repeating-linear-gradient(
              -45deg,
              #fc8181,
              #fc8181 6px,
              #e53e3e 6px,
              #e53e3e 12px
            )`,
            boxShadow: '0 0 10px rgba(252, 129, 129, 0.4)',
            transition: 'width 0.4s cubic-bezier(0.22, 1, 0.36, 1)',
            position: 'relative',
          }}
        >
          {showSpark && clamped > 0 && (
            <div
              style={{
                position: 'absolute',
                right: 0,
                top: 0,
                bottom: 0,
                width: '3px',
                background: '#ffffff',
                boxShadow: '0 0 8px #ffffff',
              }}
            />
          )}
        </div>
      </div>
    );
  }

  return (
    <div
      className="segmented-meter-track"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '3px',
        height: `${height + 4}px`,
        padding: '2px 4px',
        background: 'rgba(0, 0, 0, 0.35)',
        borderRadius: 'var(--radius-xs)',
        border: '1px solid rgba(255, 255, 255, 0.07)',
      }}
      title={label ? `${label}: ${clamped}%` : `${clamped}%`}
    >
      {Array.from({ length: totalBlocks }).map((_, idx) => {
        const isFilled = idx < filledBlocks;
        const isHead = idx === filledBlocks - 1;
        const color = getBlockColor(idx);

        return (
          <div
            key={idx}
            className={`meter-block ${isFilled ? 'active' : 'dim'} ${isHead ? 'head' : ''}`}
            style={{
              flex: 1,
              height: `${height}px`,
              borderRadius: '2px',
              backgroundColor: isFilled ? color : 'rgba(255, 255, 255, 0.06)',
              boxShadow: isFilled
                ? `0 0 6px ${color}50, inset 0 1px 0 rgba(255, 255, 255, 0.4)`
                : 'none',
              transform: isHead && showSpark ? 'scaleY(1.2)' : 'none',
              transition: 'background-color 0.2s ease, transform 0.2s ease',
              position: 'relative',
            }}
          >
            {isHead && showSpark && (
              <div
                style={{
                  position: 'absolute',
                  inset: 0,
                  borderRadius: '2px',
                  background: 'rgba(255, 255, 255, 0.5)',
                  animation: 'pulseDot 1.6s infinite',
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
};
