// Full-screen viewer for images, video and audio in the current folder.
(function () {
  'use strict';
  const { h, t, icon } = WC;

  WC.openViewer = function openViewer(items, start, kindOf) {
    let index = Math.max(0, items.indexOf(start));
    const name = h('span.viewer-name');
    const stage = h('div.viewer-stage');
    const download = h('a.iconbutton', { ariaLabel: t('fs.download') }, icon('download'));
    const element = h('dialog.viewer', null,
      h('div.viewer-bar', null, name, download,
        h('button.iconbutton', { type: 'button', ariaLabel: t('general.close'), onclick: () => element.close() }, icon('x'))),
      stage);
    let startX = null;

    function show() {
      const item = items[index];
      const kind = kindOf(item);
      name.textContent = item.name;
      download.href = item.url;
      download.download = item.name;
      let media;
      if (kind === 'image') media = h('img', { src: item.url, alt: item.name });
      else if (kind === 'video') media = h('video', { src: item.url, controls: true, autoplay: true, playsInline: true });
      else media = h('audio', { src: item.url, controls: true, autoplay: true });
      const steps = items.length > 1 ? [
        h('button.iconbutton.viewer-step.viewer-prev', { type: 'button', ariaLabel: t('general.previous'), onclick: () => step(-1) }, icon('chevron-left')),
        h('button.iconbutton.viewer-step.viewer-next', { type: 'button', ariaLabel: t('general.next'), onclick: () => step(1) }, icon('chevron-right')),
      ] : [];
      stage.replaceChildren(media, ...steps);
    }

    function step(direction) {
      index = (index + direction + items.length) % items.length;
      show();
    }

    element.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowLeft') step(-1);
      else if (event.key === 'ArrowRight') step(1);
    });
    stage.addEventListener('touchstart', (event) => {
      startX = event.touches.length === 1 ? event.touches[0].clientX : null;
    }, { passive: true });
    stage.addEventListener('touchend', (event) => {
      if (startX === null) return;
      const distance = event.changedTouches[0].clientX - startX;
      if (Math.abs(distance) > 60) step(distance < 0 ? 1 : -1);
    }, { passive: true });
    element.addEventListener('close', () => element.remove());
    document.body.append(element);
    element.showModal();
    show();
  };
})();
