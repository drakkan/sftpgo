/*
 * Minimal image viewer - zero dependencies, CSP-safe
 * Usage: ImageViewer.open(items, index)
 *   items: [{src: 'url', name: 'filename'}, ...]
 *   index: starting index
 *
 * While open, exposes --iv-scrollbar-width on <html>. Fixed elements that
 * would otherwise jump when the page scrollbar is hidden can compensate via:
 *   .my-fixed { padding-right: var(--iv-scrollbar-width, 0px); }
 */
(function() {
    'use strict';

    var overlay, imgEl, captionEl, counterEl, zoomInBtn, zoomOutBtn;
    var prevBtn, nextBtn, closeBtn, container, spinnerEl;
    var items = [];
    var currentIndex = 0;
    var scale = 1;
    var translateX = 0;
    var translateY = 0;
    var isDragging = false;
    var isTouchDrag = false;
    var dragStartX, dragStartY, dragStartTX, dragStartTY;
    var minScale = 1;
    var maxScale = 8;
    var zoomStep = 1.5;
    var loadGeneration = 0;

    // Swipe state
    var swipeStartX = 0;
    var swipeStartY = 0;
    var swipeDeltaX = 0;
    var isSwiping = false;
    var swipeActive = false;
    var swipeThreshold = 50;

    // Scrollbar compensation
    var scrollbarWidth = 0;

    // Open state
    var isOpen = false;
    var savedBodyOverflow = '';
    var savedBodyPaddingRight = '';
    var savedScrollbarVar = '';
    var scrollbarVarSet = false;
    var lastTouchEnd = 0;
    var suppressClickUntil = 0;

    // Tap detection
    var lastTapTime = 0;
    var lastTapX = 0;
    var lastTapY = 0;
    var touchStartClientX = 0;
    var touchStartClientY = 0;
    var doubleTapZoom = 2.5;

    function createElement(tag, className, parent) {
        var el = document.createElement(tag);
        if (className) el.className = className;
        if (parent) parent.appendChild(el);
        return el;
    }

    function buildDOM() {
        if (overlay) return;

        overlay = createElement('div', 'iv-overlay');

        var toolbar = createElement('div', 'iv-toolbar', overlay);
        counterEl = createElement('span', 'iv-counter', toolbar);
        var spacer = createElement('span', 'iv-spacer', toolbar);
        spacer.style.flex = '1';

        zoomInBtn = createElement('button', 'iv-btn iv-btn-zoom', toolbar);
        zoomInBtn.setAttribute('aria-label', 'Zoom in');
        zoomInBtn.innerHTML = '&#x2b;';
        zoomInBtn.addEventListener('click', function() { zoomBy(zoomStep); });

        zoomOutBtn = createElement('button', 'iv-btn iv-btn-zoom', toolbar);
        zoomOutBtn.setAttribute('aria-label', 'Zoom out');
        zoomOutBtn.innerHTML = '&#x2212;';
        zoomOutBtn.addEventListener('click', function() { zoomBy(1 / zoomStep); });

        closeBtn = createElement('button', 'iv-btn iv-btn-close', toolbar);
        closeBtn.setAttribute('aria-label', 'Close');
        closeBtn.innerHTML = '&#x2715;';
        closeBtn.addEventListener('click', close);

        container = createElement('div', 'iv-container', overlay);
        spinnerEl = createElement('div', 'iv-spinner', container);
        imgEl = createElement('img', 'iv-img', container);
        imgEl.setAttribute('draggable', 'false');

        prevBtn = createElement('button', 'iv-btn iv-btn-prev', overlay);
        prevBtn.setAttribute('aria-label', 'Previous');
        prevBtn.innerHTML = '&#x276E;';
        prevBtn.addEventListener('click', function() { navigate(-1); });

        nextBtn = createElement('button', 'iv-btn iv-btn-next', overlay);
        nextBtn.setAttribute('aria-label', 'Next');
        nextBtn.innerHTML = '&#x276F;';
        nextBtn.addEventListener('click', function() { navigate(1); });

        captionEl = createElement('div', 'iv-caption', overlay);

        overlay.addEventListener('click', function(e) {
            if (Date.now() < suppressClickUntil) return;
            if (e.target === overlay || e.target === container) {
                close();
            }
        });

        container.addEventListener('wheel', onWheel, { passive: false });
        container.addEventListener('mousedown', onMouseDragStart);
        container.addEventListener('dblclick', onDoubleClick);

        // Touch support
        var lastTouchDist = 0;
        var touchStartScale = 1;
        var pinchStartMidX = 0;
        var pinchStartMidY = 0;
        var pinchStartTX = 0;
        var pinchStartTY = 0;

        container.addEventListener('touchstart', function(e) {
            isSwiping = false;
            swipeActive = false;
            isTouchDrag = false;
            if (e.touches.length === 2) {
                lastTouchDist = getTouchDist(e);
                touchStartScale = scale;
                var startMid = getTouchMid(e);
                pinchStartMidX = startMid.x;
                pinchStartMidY = startMid.y;
                pinchStartTX = translateX;
                pinchStartTY = translateY;
            } else if (e.touches.length === 1) {
                touchStartClientX = e.touches[0].clientX;
                touchStartClientY = e.touches[0].clientY;
                if (scale > minScale) {
                    onTouchDragStart(e.touches[0]);
                } else {
                    swipeStartX = e.touches[0].clientX;
                    swipeStartY = e.touches[0].clientY;
                    swipeDeltaX = 0;
                    isSwiping = true;
                }
            }
        }, { passive: true });

        container.addEventListener('touchmove', function(e) {
            if (e.touches.length === 2) {
                e.preventDefault();
                if (lastTouchDist > 0) {
                    var dist = getTouchDist(e);
                    var newScale = clamp(touchStartScale * (dist / lastTouchDist), minScale, maxScale);
                    var mid = getTouchMid(e);
                    var factor = newScale / touchStartScale;
                    translateX = mid.x - factor * (pinchStartMidX - pinchStartTX);
                    translateY = mid.y - factor * (pinchStartMidY - pinchStartTY);
                    scale = newScale;
                    if (scale <= minScale) {
                        translateX = 0;
                        translateY = 0;
                    } else {
                        clampTranslate();
                    }
                    applyTransform();
                    updateZoomButtons();
                }
            } else if (e.touches.length === 1) {
                if (isTouchDrag) {
                    translateX = dragStartTX + (e.touches[0].clientX - dragStartX);
                    translateY = dragStartTY + (e.touches[0].clientY - dragStartY);
                    clampTranslate();
                    applyTransform();
                    e.preventDefault();
                } else if (isSwiping && items.length > 1) {
                    swipeDeltaX = e.touches[0].clientX - swipeStartX;
                    var swipeDeltaY = e.touches[0].clientY - swipeStartY;
                    if (!swipeActive && Math.abs(swipeDeltaX) > Math.abs(swipeDeltaY) * 1.5 && Math.abs(swipeDeltaX) > 10) {
                        swipeActive = true;
                    }
                    if (swipeActive) {
                        e.preventDefault();
                        imgEl.classList.remove('iv-fade');
                        translateX = swipeDeltaX;
                        applyTransform();
                        imgEl.style.opacity = String(1 - Math.abs(swipeDeltaX) / (window.innerWidth * 0.8));
                    }
                }
            }
        }, { passive: false });

        container.addEventListener('touchend', function(e) {
            if (e.touches.length === 0) {
                lastTouchEnd = Date.now();
                var changed = e.changedTouches && e.changedTouches[0];
                var moved = changed ?
                    (Math.abs(changed.clientX - touchStartClientX) > 10 ||
                     Math.abs(changed.clientY - touchStartClientY) > 10) : false;
                if (moved || isTouchDrag || swipeActive) {
                    suppressClickUntil = Date.now() + 500;
                }

                if (swipeActive && Math.abs(swipeDeltaX) > swipeThreshold && items.length > 1) {
                    navigate(swipeDeltaX > 0 ? -1 : 1);
                    isSwiping = false;
                    swipeActive = false;
                    isTouchDrag = false;
                    lastTapTime = 0;
                    return;
                }
                if (swipeActive) {
                    imgEl.classList.add('iv-fade');
                    translateX = 0;
                    applyTransform();
                    imgEl.style.opacity = '1';
                }

                if (changed && !moved && !swipeActive) {
                    var now = Date.now();
                    if (now - lastTapTime < 300 &&
                        Math.abs(changed.clientX - lastTapX) < 30 &&
                        Math.abs(changed.clientY - lastTapY) < 30) {
                        handleDoubleTap(changed.clientX, changed.clientY);
                        lastTapTime = 0;
                        suppressClickUntil = Date.now() + 500;
                    } else {
                        lastTapTime = now;
                        lastTapX = changed.clientX;
                        lastTapY = changed.clientY;
                    }
                }

                isSwiping = false;
                swipeActive = false;
                isTouchDrag = false;
            }
        }, { passive: true });

        document.body.appendChild(overlay);
    }

    function getTouchDist(e) {
        var dx = e.touches[0].clientX - e.touches[1].clientX;
        var dy = e.touches[0].clientY - e.touches[1].clientY;
        return Math.sqrt(dx * dx + dy * dy);
    }

    function getTouchMid(e) {
        var rect = container.getBoundingClientRect();
        var mx = (e.touches[0].clientX + e.touches[1].clientX) / 2;
        var my = (e.touches[0].clientY + e.touches[1].clientY) / 2;
        return { x: mx - (rect.left + rect.width / 2), y: my - (rect.top + rect.height / 2) };
    }

    function clamp(val, min, max) {
        return Math.min(Math.max(val, min), max);
    }

    function clampTranslate() {
        if (scale <= minScale) {
            translateX = 0;
            translateY = 0;
            return;
        }
        var rect = container.getBoundingClientRect();
        // Calculate actual rendered image size (respecting object-fit: contain)
        var natW = imgEl.naturalWidth;
        var natH = imgEl.naturalHeight;
        var boxW = imgEl.offsetWidth;
        var boxH = imgEl.offsetHeight;
        var displayW = boxW;
        var displayH = boxH;
        if (natW && natH) {
            var ratio = Math.min(boxW / natW, boxH / natH);
            displayW = natW * ratio;
            displayH = natH * ratio;
        }
        // Scaled size
        var scaledW = displayW * scale;
        var scaledH = displayH * scale;
        // Max translate: half the overflow on each side
        var maxTX = Math.max(0, (scaledW - rect.width) / 2);
        var maxTY = Math.max(0, (scaledH - rect.height) / 2);
        translateX = clamp(translateX, -maxTX, maxTX);
        translateY = clamp(translateY, -maxTY, maxTY);
    }

    function setScale(s) {
        scale = s;
        if (scale <= minScale) {
            translateX = 0;
            translateY = 0;
        } else {
            clampTranslate();
        }
        updateZoomButtons();
    }

    function updateZoomButtons() {
        zoomInBtn.disabled = scale >= maxScale;
        zoomOutBtn.disabled = scale <= minScale;
    }

    function applyTransform() {
        imgEl.style.transform = 'translate(' + translateX + 'px, ' + translateY + 'px) scale(' + scale + ')';
        updateCursor();
    }

    function updateCursor() {
        imgEl.style.cursor = scale > minScale ? 'grab' : '';
    }

    function resetTransform() {
        scale = minScale;
        translateX = 0;
        translateY = 0;
        applyTransform();
        updateZoomButtons();
    }

    function zoomBy(factor) {
        var newScale = clamp(scale * factor, minScale, maxScale);
        if (newScale !== scale) {
            setScale(newScale);
            applyTransform();
        }
    }

    function onWheel(e) {
        e.preventDefault();
        var delta = e.deltaY > 0 ? 0.9 : 1.1;
        var newScale = clamp(scale * delta, minScale, maxScale);
        if (newScale !== scale) {
            var rect = container.getBoundingClientRect();
            var cx = e.clientX - (rect.left + rect.width / 2);
            var cy = e.clientY - (rect.top + rect.height / 2);
            var factor = newScale / scale;
            translateX = cx - factor * (cx - translateX);
            translateY = cy - factor * (cy - translateY);
            scale = newScale;
            clampTranslate();
            applyTransform();
            updateZoomButtons();
        }
    }

    function onDoubleClick(e) {
        if (Date.now() - lastTouchEnd < 500) return;
        handleDoubleTap(e.clientX, e.clientY);
    }

    function handleDoubleTap(clientX, clientY) {
        if (scale > minScale) {
            resetTransform();
            return;
        }
        var rect = container.getBoundingClientRect();
        var cx = clientX - (rect.left + rect.width / 2);
        var cy = clientY - (rect.top + rect.height / 2);
        var newScale = clamp(doubleTapZoom, minScale, maxScale);
        var factor = newScale / scale;
        translateX = cx - factor * (cx - translateX);
        translateY = cy - factor * (cy - translateY);
        scale = newScale;
        clampTranslate();
        applyTransform();
        updateZoomButtons();
    }

    // Mouse drag — only used on non-touch devices
    function onMouseDragStart(e) {
        if (scale <= minScale) return;
        isDragging = true;
        dragStartX = e.clientX;
        dragStartY = e.clientY;
        dragStartTX = translateX;
        dragStartTY = translateY;
        imgEl.style.cursor = 'grabbing';
        document.addEventListener('mousemove', onMouseDragMove);
        document.addEventListener('mouseup', onMouseDragEnd);
    }

    function onMouseDragMove(e) {
        if (!isDragging) return;
        translateX = dragStartTX + (e.clientX - dragStartX);
        translateY = dragStartTY + (e.clientY - dragStartY);
        clampTranslate();
        applyTransform();
    }

    function onMouseDragEnd() {
        isDragging = false;
        updateCursor();
        document.removeEventListener('mousemove', onMouseDragMove);
        document.removeEventListener('mouseup', onMouseDragEnd);
    }

    // Touch drag — separate from mouse, no document listeners
    function onTouchDragStart(touch) {
        isTouchDrag = true;
        dragStartX = touch.clientX;
        dragStartY = touch.clientY;
        dragStartTX = translateX;
        dragStartTY = translateY;
    }

    function showItem(index) {
        currentIndex = index;
        var item = items[index];
        var gen = ++loadGeneration;

        imgEl.classList.add('iv-fade');
        imgEl.style.opacity = '0';
        spinnerEl.style.display = '';
        resetTransform();

        imgEl.onload = function() {
            if (gen !== loadGeneration) return;
            imgEl.style.opacity = '1';
            spinnerEl.style.display = 'none';
        };
        imgEl.onerror = function() {
            if (gen !== loadGeneration) return;
            imgEl.style.opacity = '1';
            spinnerEl.style.display = 'none';
        };
        imgEl.src = item.src;
        if (imgEl.complete && imgEl.naturalWidth > 0) {
            imgEl.style.opacity = '1';
            spinnerEl.style.display = 'none';
        }

        captionEl.textContent = item.name || '';
        counterEl.textContent = items.length > 1 ? (index + 1) + ' / ' + items.length : '';

        prevBtn.style.display = items.length > 1 ? '' : 'none';
        nextBtn.style.display = items.length > 1 ? '' : 'none';
    }

    function navigate(dir) {
        if (!items.length) return;
        var newIndex = currentIndex + dir;
        if (newIndex < 0) newIndex = items.length - 1;
        if (newIndex >= items.length) newIndex = 0;
        showItem(newIndex);
    }

    function onKeyDown(e) {
        switch (e.key) {
            case 'Escape': close(); break;
            case 'ArrowLeft': navigate(-1); break;
            case 'ArrowRight': navigate(1); break;
        }
    }

    function getScrollbarWidth() {
        return window.innerWidth - document.documentElement.clientWidth;
    }

    function open(itemList, startIndex) {
        buildDOM();
        items = itemList || [];
        if (!items.length) return;

        if (!isOpen) {
            savedBodyOverflow = document.body.style.overflow;
            savedBodyPaddingRight = document.body.style.paddingRight;
            scrollbarWidth = getScrollbarWidth();
            document.body.style.overflow = 'hidden';
            if (scrollbarWidth > 0) {
                var currentPad = parseFloat(window.getComputedStyle(document.body).paddingRight) || 0;
                document.body.style.paddingRight = (currentPad + scrollbarWidth) + 'px';
                savedScrollbarVar = document.documentElement.style.getPropertyValue('--iv-scrollbar-width');
                document.documentElement.style.setProperty('--iv-scrollbar-width', scrollbarWidth + 'px');
                scrollbarVarSet = true;
            }
            document.addEventListener('keydown', onKeyDown);
            isOpen = true;
        }
        overlay.classList.add('iv-visible');
        showItem(clamp(startIndex || 0, 0, items.length - 1));
    }

    function close() {
        if (!overlay || !isOpen) return;
        if (isDragging) {
            onMouseDragEnd();
        }
        isSwiping = false;
        swipeActive = false;
        isTouchDrag = false;
        overlay.classList.remove('iv-visible');
        document.body.style.overflow = savedBodyOverflow;
        document.body.style.paddingRight = savedBodyPaddingRight;
        if (scrollbarVarSet) {
            if (savedScrollbarVar) {
                document.documentElement.style.setProperty('--iv-scrollbar-width', savedScrollbarVar);
            } else {
                document.documentElement.style.removeProperty('--iv-scrollbar-width');
            }
            scrollbarVarSet = false;
        }
        document.removeEventListener('keydown', onKeyDown);
        imgEl.onload = null;
        imgEl.onerror = null;
        imgEl.removeAttribute('src');
        spinnerEl.style.display = 'none';
        lastTapTime = 0;
        suppressClickUntil = 0;
        isOpen = false;
    }

    window.ImageViewer = {
        open: open,
        close: close
    };
})();
