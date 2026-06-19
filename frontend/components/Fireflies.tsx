"use client";

import { useEffect } from "react";

export default function Fireflies() {
  useEffect(() => {
    const colors = ["firefly-violet", "firefly-mint", "firefly-sky"];
    const count = 8;

    function createFireflies() {
      const existing = document.querySelectorAll(".firefly");
      existing.forEach((f) => f.remove());

      for (let i = 0; i < count; i++) {
        const firefly = document.createElement("div");
        const color = colors[Math.floor(Math.random() * colors.length)];

        firefly.className = `firefly ${color}`;

        const startX = Math.random() * window.innerWidth;
        const startY = Math.random() * window.innerHeight;

        firefly.style.left = `${startX}px`;
        firefly.style.top = `${startY}px`;

        firefly.style.animationDelay = `${Math.random() * 3}s`;

        document.body.appendChild(firefly);
      }
    }

    createFireflies();
    const interval = setInterval(createFireflies, 12000);

    return () => clearInterval(interval);
  }, []);

  return null;
}
