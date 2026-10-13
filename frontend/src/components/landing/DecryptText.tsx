import React, { useEffect, useState, useRef } from 'react';

interface DecryptTextProps {
  text: string;
  speed?: number;
  maxIterations?: number;
  characters?: string;
  className?: string;
  animateOnHover?: boolean;
}

const GLYPHS = 'ABCDEF0123456789_#@<>[]*&$%+=';

export const DecryptText: React.FC<DecryptTextProps> = ({
  text,
  speed = 28,
  maxIterations = 14,
  characters = GLYPHS,
  className = '',
  animateOnHover = false,
}) => {
  const [displayText, setDisplayText] = useState<string>(text);
  const isAnimatingRef = useRef<boolean>(false);

  const startAnimation = () => {
    if (isAnimatingRef.current) return;
    isAnimatingRef.current = true;
    let iteration = 0;

    const interval = setInterval(() => {
      setDisplayText(() =>
        text
          .split('')
          .map((char, index) => {
            if (char === ' ') return ' ';
            if (index < iteration) {
              return text[index];
            }
            return characters[Math.floor(Math.random() * characters.length)];
          })
          .join('')
      );

      if (iteration >= text.length) {
        clearInterval(interval);
        setDisplayText(text);
        isAnimatingRef.current = false;
      }

      iteration += 1 / (maxIterations / text.length);
    }, speed);
  };

  useEffect(() => {
    startAnimation();
  }, [text]);

  return (
    <span
      className={`decrypt-text ${className}`}
      onMouseEnter={animateOnHover ? startAnimation : undefined}
      style={{
        display: 'inline-block',
        fontFamily: 'inherit',
        letterSpacing: 'inherit',
      }}
    >
      {displayText}
    </span>
  );
};
