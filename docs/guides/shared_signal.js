(function () {
  let signalRefs = null;
  let animationHandle = 0;
  let booted = false;
  const reducedMotion = window.matchMedia
    ? window.matchMedia("(prefers-reduced-motion: reduce)")
    : null;

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function positiveModulo(value, modulo) {
    const result = value % modulo;
    return result < 0 ? result + modulo : result;
  }

  function themeToken(name, fallback) {
    const value = window.getComputedStyle(document.documentElement).getPropertyValue(name);
    return value ? value.trim() : fallback;
  }

  function applySignalGradient(gradientEl, stopEls, color, startX, startY, endX, endY, hot) {
    if (!gradientEl || !stopEls || stopEls.length < 4) {
      return;
    }
    gradientEl.setAttribute("x1", startX.toFixed(2));
    gradientEl.setAttribute("y1", startY.toFixed(2));
    gradientEl.setAttribute("x2", endX.toFixed(2));
    gradientEl.setAttribute("y2", endY.toFixed(2));
    stopEls[0].setAttribute("stop-color", color);
    stopEls[0].setAttribute("stop-opacity", "0");
    stopEls[1].setAttribute("stop-color", color);
    stopEls[1].setAttribute("stop-opacity", hot ? "0.96" : "0.74");
    stopEls[2].setAttribute("stop-color", color);
    stopEls[2].setAttribute("stop-opacity", hot ? "0.86" : "0.56");
    stopEls[3].setAttribute("stop-color", color);
    stopEls[3].setAttribute("stop-opacity", "0");
  }

  function docsSignalPath(startX, startY, endX, endY, timeSeconds, laneIndex) {
    const spanX = Math.max(endX - startX, 1);
    const lift0 = 42 + (laneIndex * 16) + (Math.sin((timeSeconds * 0.26) + laneIndex) * 10);
    const lift1 = 34 + (laneIndex * 12) + (Math.cos((timeSeconds * 0.22) + (laneIndex * 0.7)) * 11);
    const bend0 = Math.cos((timeSeconds * 0.18) + (laneIndex * 1.2)) * 18;
    const bend1 = Math.sin((timeSeconds * 0.15) + (laneIndex * 1.5)) * 22;
    const c1x = startX + (spanX * (0.22 + (laneIndex * 0.03))) + bend0;
    const c1y = startY - lift0;
    const c2x = startX + (spanX * (0.74 - (laneIndex * 0.04))) + bend1;
    const c2y = endY + lift1;
    return `M ${startX.toFixed(2)} ${startY.toFixed(2)} C ${c1x.toFixed(2)} ${c1y.toFixed(2)}, ${c2x.toFixed(2)} ${c2y.toFixed(2)}, ${endX.toFixed(2)} ${endY.toFixed(2)}`;
  }

  function signalPulseTruth(timeSeconds, periodSeconds, visibleRatio, offsetSeconds) {
    const phase = positiveModulo(timeSeconds + offsetSeconds, periodSeconds) / periodSeconds;
    if (phase > visibleRatio) {
      return {
        active: false,
        progress: 0,
        alpha: 0
      };
    }
    const progress = clamp(phase / Math.max(visibleRatio, 0.01), 0, 1);
    return {
      active: true,
      progress,
      alpha: Math.sin(progress * Math.PI)
    };
  }

  function signalPulseStyle(timeSeconds, periodSeconds, visibleRatio, pulseLength, offsetSeconds, baseOpacity, glowFactor) {
    const pulse = signalPulseTruth(timeSeconds, periodSeconds, visibleRatio, offsetSeconds);
    const dashLength = clamp(pulseLength, 1.5, 26);
    const dashGap = Math.max(100 - dashLength, 1);
    const dashOffset = -(pulse.progress * 100);
    const coreOpacity = pulse.active ? baseOpacity * pulse.alpha : 0;
    const glowOpacity = pulse.active ? baseOpacity * glowFactor * pulse.alpha : 0;
    return {
      core: `stroke-dasharray:${dashLength.toFixed(2)} ${dashGap.toFixed(2)};stroke-dashoffset:${dashOffset.toFixed(2)};opacity:${coreOpacity.toFixed(3)};`,
      glow: `stroke-dasharray:${dashLength.toFixed(2)} ${dashGap.toFixed(2)};stroke-dashoffset:${dashOffset.toFixed(2)};opacity:${glowOpacity.toFixed(3)};`
    };
  }

  function rectFor(selector, fallbackRect) {
    const node = document.querySelector(selector);
    return node ? node.getBoundingClientRect() : fallbackRect;
  }

  function ensureSignalLayer() {
    if (signalRefs && document.body && document.body.contains(signalRefs.layer)) {
      return signalRefs;
    }
    if (!document.body) {
      return null;
    }

    let layer = document.querySelector(".docs-signal-layer");
    if (!layer) {
      layer = document.createElement("div");
      layer.className = "docs-signal-layer";
      layer.setAttribute("aria-hidden", "true");
      layer.innerHTML = `
        <svg class="docs-signal-svg" viewBox="0 0 100 100" preserveAspectRatio="none">
          <defs>
            <filter id="docs-signal-glow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="3.8"></feGaussianBlur>
            </filter>
            <linearGradient id="docs-signal-gradient-primary" gradientUnits="userSpaceOnUse">
              <stop id="docs-signal-primary-stop-0" offset="0%" stop-color="#6dc7dd" stop-opacity="0"></stop>
              <stop id="docs-signal-primary-stop-1" offset="18%" stop-color="#6dc7dd" stop-opacity="0.9"></stop>
              <stop id="docs-signal-primary-stop-2" offset="82%" stop-color="#6dc7dd" stop-opacity="0.82"></stop>
              <stop id="docs-signal-primary-stop-3" offset="100%" stop-color="#6dc7dd" stop-opacity="0"></stop>
            </linearGradient>
            <linearGradient id="docs-signal-gradient-risk" gradientUnits="userSpaceOnUse">
              <stop id="docs-signal-risk-stop-0" offset="0%" stop-color="#e632d7" stop-opacity="0"></stop>
              <stop id="docs-signal-risk-stop-1" offset="18%" stop-color="#e632d7" stop-opacity="0.78"></stop>
              <stop id="docs-signal-risk-stop-2" offset="82%" stop-color="#e632d7" stop-opacity="0.72"></stop>
              <stop id="docs-signal-risk-stop-3" offset="100%" stop-color="#e632d7" stop-opacity="0"></stop>
            </linearGradient>
          </defs>
          <g id="docs-signal-ambient"></g>
          <path id="docs-signal-primary-glow" class="docs-signal-glow docs-signal-primary-glow" pathLength="100" d=""></path>
          <path id="docs-signal-risk-glow" class="docs-signal-glow docs-signal-risk-glow" pathLength="100" d=""></path>
          <path id="docs-signal-primary-path" class="docs-signal-path docs-signal-primary-path" pathLength="100" d=""></path>
          <path id="docs-signal-risk-path" class="docs-signal-path docs-signal-risk-path" pathLength="100" d=""></path>
        </svg>
      `;
      document.body.prepend(layer);
    }

    signalRefs = {
      layer,
      svg: layer.querySelector(".docs-signal-svg"),
      ambient: layer.querySelector("#docs-signal-ambient"),
      primaryPath: layer.querySelector("#docs-signal-primary-path"),
      primaryGlow: layer.querySelector("#docs-signal-primary-glow"),
      riskPath: layer.querySelector("#docs-signal-risk-path"),
      riskGlow: layer.querySelector("#docs-signal-risk-glow"),
      primaryGradient: layer.querySelector("#docs-signal-gradient-primary"),
      riskGradient: layer.querySelector("#docs-signal-gradient-risk"),
      primaryStops: [
        layer.querySelector("#docs-signal-primary-stop-0"),
        layer.querySelector("#docs-signal-primary-stop-1"),
        layer.querySelector("#docs-signal-primary-stop-2"),
        layer.querySelector("#docs-signal-primary-stop-3")
      ],
      riskStops: [
        layer.querySelector("#docs-signal-risk-stop-0"),
        layer.querySelector("#docs-signal-risk-stop-1"),
        layer.querySelector("#docs-signal-risk-stop-2"),
        layer.querySelector("#docs-signal-risk-stop-3")
      ]
    };

    return signalRefs;
  }

  function layoutSnapshot(width, height) {
    const fallbackRect = {
      left: 18,
      top: 18,
      right: Math.max(width - 18, 19),
      bottom: Math.max(height - 18, 19),
      width: Math.max(width - 36, 1),
      height: Math.max(height - 36, 1)
    };
    const shellRect = rectFor(".shell", fallbackRect);
    const pageRect = rectFor(".doc-page", shellRect);
    const hasMenu = Boolean(document.querySelector(".left-menu"));
    const menuRect = hasMenu ? rectFor(".left-menu", shellRect) : pageRect;
    const mainRect = document.querySelector(".main-shell")
      ? rectFor(".main-shell", pageRect)
      : pageRect;
    const topRect = document.querySelector(".top-menu")
      ? rectFor(".top-menu", pageRect)
      : pageRect;
    const clampX = function (value) {
      return clamp(value, 18, width - 18);
    };
    const clampY = function (value) {
      return clamp(value, 18, height - 18);
    };

    return {
      width,
      height,
      hasMenu,
      clampX,
      clampY,
      primaryStartX: hasMenu
        ? clampX(menuRect.right - 28)
        : clampX(pageRect.left + Math.min(pageRect.width * 0.12, 56)),
      primaryStartY: hasMenu
        ? clampY(pageRect.bottom - 128)
        : clampY(pageRect.bottom - 96),
      primaryEndX: clampX(mainRect.right - 56),
      primaryEndY: clampY(topRect.top + Math.min(topRect.height + 26, 86)),
      riskStartX: hasMenu
        ? clampX(shellRect.left + 28)
        : clampX(pageRect.left + 18),
      riskStartY: clampY(pageRect.bottom - 44),
      riskEndX: clampX(mainRect.right - 118),
      riskEndY: clampY(pageRect.top + Math.min(pageRect.height * 0.14, 118))
    };
  }

  function renderDocsSignalsAt(timeSeconds) {
    const refs = ensureSignalLayer();
    if (!refs || !refs.svg) {
      return;
    }

    const width = Math.max(window.innerWidth || 0, document.documentElement.clientWidth || 0, 320);
    const height = Math.max(window.innerHeight || 0, document.documentElement.clientHeight || 0, 240);
    const layout = layoutSnapshot(width, height);
    const primaryColor = themeToken("--ui-active", "#6dc7dd");
    const riskColor = themeToken("--ui-recommendation", "#e632d7");
    const primaryPath = docsSignalPath(
      layout.primaryStartX,
      layout.primaryStartY,
      layout.primaryEndX,
      layout.primaryEndY,
      timeSeconds,
      0
    );
    const riskPath = docsSignalPath(
      layout.riskStartX,
      layout.riskStartY,
      layout.riskEndX,
      layout.riskEndY,
      timeSeconds,
      3
    );
    const primaryPulse = signalPulseStyle(timeSeconds, 12.4, 0.11, 10.5, 0.25, 0.92, 0.8);
    const riskPulse = signalPulseStyle(timeSeconds, 14.8, 0.095, 9.4, 1.8, 0.76, 0.72);
    const ambientMarkup = [
      {
        className: "docs-signal-ambient-path docs-signal-ambient-primary",
        d: docsSignalPath(
          layout.clampX(layout.primaryStartX + 18),
          layout.clampY(layout.primaryStartY - 54),
          layout.clampX(layout.primaryEndX - 28),
          layout.clampY(layout.primaryEndY - 18),
          timeSeconds,
          5
        ),
        style: "opacity:0.18;"
      },
      {
        className: "docs-signal-ambient-path docs-signal-ambient-primary",
        d: docsSignalPath(
          layout.clampX(layout.primaryStartX + 42),
          layout.clampY(layout.primaryStartY - 98),
          layout.clampX(layout.primaryEndX - 82),
          layout.clampY(layout.primaryEndY + 18),
          timeSeconds,
          7
        ),
        style: "opacity:0.12;"
      },
      {
        className: "docs-signal-ambient-path docs-signal-ambient-risk",
        d: docsSignalPath(
          layout.clampX(layout.riskStartX + 10),
          layout.clampY(layout.riskStartY - 12),
          layout.clampX(layout.riskEndX + 22),
          layout.clampY(layout.riskEndY + 42),
          timeSeconds,
          6
        ),
        style: "opacity:0.14;"
      },
      {
        className: "docs-signal-ambient-path docs-signal-ambient-risk",
        d: docsSignalPath(
          layout.clampX(layout.riskStartX + 38),
          layout.clampY(layout.riskStartY + 46),
          layout.clampX(layout.riskEndX - 34),
          layout.clampY(layout.riskEndY + 86),
          timeSeconds,
          8
        ),
        style: "opacity:0.1;"
      }
    ];
    const riskHot = Math.sin(timeSeconds * 0.18) > 0.2;

    refs.svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    refs.primaryPath.setAttribute("d", primaryPath);
    refs.primaryGlow.setAttribute("d", primaryPath);
    refs.riskPath.setAttribute("d", riskPath);
    refs.riskGlow.setAttribute("d", riskPath);
    refs.primaryPath.setAttribute("style", primaryPulse.core);
    refs.primaryGlow.setAttribute("style", primaryPulse.glow);
    refs.riskPath.setAttribute("style", riskPulse.core);
    refs.riskGlow.setAttribute("style", riskPulse.glow);
    refs.ambient.innerHTML = ambientMarkup
      .map(function (entry) {
        return `<path class="${entry.className}" pathLength="100" d="${entry.d}" style="${entry.style}"></path>`;
      })
      .join("");

    applySignalGradient(
      refs.primaryGradient,
      refs.primaryStops,
      primaryColor,
      layout.primaryStartX,
      layout.primaryStartY,
      layout.primaryEndX,
      layout.primaryEndY,
      true
    );
    applySignalGradient(
      refs.riskGradient,
      refs.riskStops,
      riskColor,
      layout.riskStartX,
      layout.riskStartY,
      layout.riskEndX,
      layout.riskEndY,
      riskHot
    );
    refs.layer.style.opacity = width < 720 ? "0.72" : "0.92";
  }

  function stopAnimation() {
    if (!animationHandle) {
      return;
    }
    window.cancelAnimationFrame(animationHandle);
    animationHandle = 0;
  }

  function animateDocsSignals(timestamp) {
    renderDocsSignalsAt((timestamp || 0) * 0.001);
    animationHandle = window.requestAnimationFrame(animateDocsSignals);
  }

  function refreshSignals() {
    stopAnimation();
    renderDocsSignalsAt((window.performance.now ? window.performance.now() : Date.now()) * 0.001);
    if (!reducedMotion || !reducedMotion.matches) {
      animationHandle = window.requestAnimationFrame(animateDocsSignals);
    }
  }

  function handleResize() {
    renderDocsSignalsAt((window.performance.now ? window.performance.now() : Date.now()) * 0.001);
  }

  function handleVisibilityChange() {
    if (document.hidden) {
      stopAnimation();
      return;
    }
    refreshSignals();
  }

  function boot() {
    if (booted) {
      refreshSignals();
      return;
    }
    booted = true;
    ensureSignalLayer();
    refreshSignals();
    window.addEventListener("resize", handleResize, { passive: true });
    document.addEventListener("visibilitychange", handleVisibilityChange);
    if (reducedMotion) {
      if (reducedMotion.addEventListener) {
        reducedMotion.addEventListener("change", refreshSignals);
      } else if (reducedMotion.addListener) {
        reducedMotion.addListener(refreshSignals);
      }
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
