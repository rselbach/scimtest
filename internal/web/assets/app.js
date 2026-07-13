    // Flash toast: auto-dismiss + click-to-dismiss.
    (function () {
      const flash = document.querySelector('[data-flash]');
      if (!flash) return;
      let dismissed = false;
      const dismiss = () => {
        if (dismissed) return;
        dismissed = true;
        flash.classList.add('is-leaving');
        const cleanup = () => flash.remove();
        flash.addEventListener('animationend', cleanup, { once: true });
        // Fallback in case the animation is suppressed (reduced-motion, etc.).
        setTimeout(cleanup, 400);
      };
      const closeBtn = flash.querySelector('.flash-close');
      if (closeBtn) closeBtn.addEventListener('click', dismiss);
	  if (document.body.dataset.flashError !== 'true') setTimeout(dismiss, 4000);
    })();

    async function writeClipboard(text) {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
      }

      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.top = '-1000px';
      textarea.style.left = '-1000px';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        if (!document.execCommand('copy')) {
          throw new Error('copy failed');
        }
      } finally {
        textarea.remove();
      }
    }

	const copyButtons = document.querySelectorAll('[data-copy-button]');
	const copyStatus = document.querySelector('[data-copy-status]');
    for (const button of copyButtons) {
      button.addEventListener('click', async function () {
        const field = button.closest('.copy-field');
        const value = field ? field.querySelector('.v') : null;
        const text = value ? value.innerText.trim() : '';
        if (!text) return;

        const originalTitle = button.getAttribute('title') || 'Copy';
        try {
          await writeClipboard(text);
          button.classList.add('is-copied');
          button.setAttribute('title', 'Copied');
		  button.setAttribute('aria-label', 'Copied');
		  if (copyStatus) copyStatus.textContent = 'Copied to clipboard';
          setTimeout(function () {
            button.classList.remove('is-copied');
            button.setAttribute('title', originalTitle);
            button.setAttribute('aria-label', originalTitle);
          }, 1200);
        } catch (err) {
		  button.setAttribute('title', 'Copy failed');
		  if (copyStatus) copyStatus.textContent = 'Copy failed';
          setTimeout(function () {
            button.setAttribute('title', originalTitle);
          }, 1200);
		}
	      });
	    }

	for (const button of document.querySelectorAll('[data-secret-toggle]')) {
	  button.addEventListener('click', function () {
		const field = button.closest('.field');
		const input = field ? field.querySelector('[data-secret-input]') : null;
		if (!input) return;
		const showing = input.type === 'text';
		input.type = showing ? 'password' : 'text';
		button.textContent = showing ? 'Show' : 'Hide';
	  });
	}

	const testSCIMButton = document.querySelector('[data-test-scim]');
	if (testSCIMButton) {
	  testSCIMButton.addEventListener('click', async function () {
		const form = testSCIMButton.closest('form');
		const status = form ? form.querySelector('[data-test-scim-status]') : null;
		if (!form || !status) return;
		testSCIMButton.disabled = true;
		status.textContent = 'Testing connection…';
		try {
		  const response = await fetch('/apps/test-scim', {
			method: 'POST',
			body: new FormData(form),
			headers: { 'Accept': 'application/json', 'X-Requested-With': 'fetch' }
		  });
		  const result = await response.json();
		  if (!response.ok) throw new Error(result.error || 'Connection test failed');
		  status.textContent = result.message;
		} catch (err) {
		  status.textContent = err.message;
		} finally {
		  testSCIMButton.disabled = false;
		}
	  });
	}

	const memberPicker = document.querySelector('[data-member-picker]');
	if (memberPicker) {
	  const search = memberPicker.querySelector('[data-member-search]');
	  const options = Array.from(memberPicker.querySelectorAll('[data-member-option]'));
	  const status = memberPicker.querySelector('[data-member-status]');
	  const empty = memberPicker.querySelector('[data-member-empty]');
	  const more = memberPicker.querySelector('[data-member-more]');
	  const pageSize = 50;
	  let visibleLimit = pageSize;

	  function updateMemberPicker() {
		const query = (search.value || '').trim().toLocaleLowerCase();
		const matches = options.filter(option => (option.dataset.memberTerms || '').toLocaleLowerCase().includes(query));
		const matchSet = new Set(matches);
		let shown = 0;
		for (const option of options) {
		  const matchesSearch = matchSet.has(option);
		  const checked = option.querySelector('input').checked;
		  const visible = matchesSearch && (shown < visibleLimit || (query === '' && checked));
		  option.classList.toggle('is-hidden', !visible);
		  if (visible) shown++;
		}
		const selected = options.filter(option => option.querySelector('input').checked).length;
		status.textContent = 'Showing ' + String(shown) + ' of ' + String(matches.length) + ' · ' + String(selected) + ' selected';
		empty.classList.toggle('is-hidden', matches.length !== 0);
		more.classList.toggle('is-hidden', shown >= matches.length);
	  }

	  search.addEventListener('input', function () {
		visibleLimit = pageSize;
		updateMemberPicker();
	  });
	  memberPicker.addEventListener('change', updateMemberPicker);
	  more.addEventListener('click', function () {
		visibleLimit += pageSize;
		updateMemberPicker();
	  });
	  updateMemberPicker();
	}

    const overlays = Array.from(document.querySelectorAll('[data-overlay]'));
	const activeOverlay = overlays[overlays.length - 1];
	const formError = document.querySelector('[data-form-error]');
	if (activeOverlay && formError) {
	  const modalBody = activeOverlay.querySelector('.modal-body');
	  if (modalBody) modalBody.prepend(formError);
	}

    // Esc and backdrop clicks discard the modal; ask first once the user
    // has typed into it. Explicit Cancel/Close links stay unguarded.
    let overlayFormDirty = false;
    if (activeOverlay) {
      activeOverlay.addEventListener('input', function (event) {
        if (event.target.closest('form')) overlayFormDirty = true;
      });
    }

    function closeActiveOverlay() {
      if (!activeOverlay) return;
      if (overlayFormDirty && !window.confirm('Discard unsaved changes?')) return;
      const closeLink = activeOverlay.querySelector('a[href]');
      if (closeLink) {
        window.location.href = closeLink.href;
      }
    }

    if (activeOverlay) {
      const modal = activeOverlay.querySelector('[role="dialog"]');
      const focusableSelectors = [
        'button:not([disabled])',
        '[href]',
		'input:not([type="hidden"]):not([disabled])',
        'select:not([disabled])',
        'textarea:not([disabled])',
        '[tabindex]:not([tabindex="-1"])'
      ].join(',');
      const focusableElements = Array.from(activeOverlay.querySelectorAll(focusableSelectors));

	  for (const region of document.querySelectorAll('.topbar, .app, .footer')) {
		region.setAttribute('inert', '');
		region.setAttribute('aria-hidden', 'true');
      }

	  const preferredFocus = activeOverlay.querySelector('[data-autofocus]:not([disabled])');
      const initialFocus = preferredFocus || focusableElements[0] || modal;
      if (initialFocus) {
        initialFocus.focus();
      }

      activeOverlay.addEventListener('keydown', function (event) {
        if (event.key !== 'Tab' || focusableElements.length === 0) {
          return;
        }

        const first = focusableElements[0];
        const last = focusableElements[focusableElements.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
          return;
        }

        if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      });

      // Click on the backdrop (not on the modal itself) closes the overlay.
      // Track mousedown so a drag starting inside the modal that releases on
      // the backdrop (e.g. text-selection overshoot) does not trigger close.
      let mouseDownOnBackdrop = false;
      activeOverlay.addEventListener('mousedown', function (event) {
        mouseDownOnBackdrop = event.target === activeOverlay;
      });
      activeOverlay.addEventListener('mouseup', function (event) {
        if (mouseDownOnBackdrop && event.target === activeOverlay) {
          closeActiveOverlay();
        }
        mouseDownOnBackdrop = false;
      });
    }

    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') return;
      closeActiveOverlay();
    });

    const protocolControls = document.querySelectorAll('input[name="protocol"]');
    const protocolSections = document.querySelectorAll('[data-protocol-section]');
    function syncProtocolSections() {
      const selectedControl = document.querySelector('input[name="protocol"]:checked');
      if (!selectedControl) return;
      const selected = selectedControl.value;
      for (const section of protocolSections) {
        const visible = selected === 'both' || section.dataset.protocolSection === selected;
        section.classList.toggle('is-hidden', !visible);
        for (const control of section.querySelectorAll('input, textarea, select')) {
          control.disabled = !visible;
        }
      }
    }
    if (protocolControls.length) {
      for (const control of protocolControls) {
        control.addEventListener('change', syncProtocolSections);
      }
      syncProtocolSections();
    }

	const scimToggle = document.querySelector('[data-scim-toggle]');
	const scimSection = document.querySelector('[data-scim-section]');
	function syncSCIMSection() {
	  if (!scimToggle || !scimSection) return;
	  const selectedProtocol = document.querySelector('input[name="protocol"]:checked');
	  if (selectedProtocol && selectedProtocol.value === 'scim') {
		scimToggle.checked = true;
	  }
	  scimSection.classList.toggle('is-hidden', !scimToggle.checked);
	  for (const control of scimSection.querySelectorAll('input, textarea, select')) {
		control.disabled = !scimToggle.checked;
	  }
	}
	if (scimToggle) {
	  scimToggle.addEventListener('change', syncSCIMSection);
	  for (const control of protocolControls) {
		control.addEventListener('change', syncSCIMSection);
	  }
	  syncSCIMSection();
	}

    const environmentForm = document.querySelector('[data-environment-form]');
    if (environmentForm && !environmentForm.elements.id.value) {
      const environmentName = environmentForm.querySelector('[data-environment-name]');
      const environmentSlug = environmentForm.querySelector('[data-environment-slug]');
      let slugIsAutomatic = environmentSlug && environmentSlug.value.trim() === '';

      function slugifyEnvironmentName(name) {
        return name.toLowerCase().trim()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '');
      }

      function syncEnvironmentSlug() {
        if (!slugIsAutomatic || !environmentName || !environmentSlug) return;
        environmentSlug.value = slugifyEnvironmentName(environmentName.value);
      }

      if (environmentName && environmentSlug) {
        environmentName.addEventListener('input', syncEnvironmentSlug);
        environmentSlug.addEventListener('input', function () {
          slugIsAutomatic = environmentSlug.value.trim() === '';
          syncEnvironmentSlug();
        });
        syncEnvironmentSlug();
      }
    }

    function listURLFromForm(form) {
      const url = new URL(form.action, window.location.href);
      const data = new FormData(form);
      for (const [key, value] of data.entries()) {
        if (String(value).trim() === '') {
          url.searchParams.delete(key);
          continue;
        }
        url.searchParams.set(key, value);
      }
      url.searchParams.delete('page');
      return url;
    }

    function cleanListURL(url) {
      const clean = new URL(url.href);
      clean.searchParams.delete('partial');
      return clean;
    }

    let listUpdateID = 0;
    async function replaceListCard(url) {
      const card = document.querySelector('[data-list-card]');
      if (!card) return;

      const updateID = ++listUpdateID;
      const active = document.activeElement;
      const restoreSearchFocus = active && active.matches('[data-list-search]');
      const selectionStart = restoreSearchFocus ? active.selectionStart : null;
      const selectionEnd = restoreSearchFocus ? active.selectionEnd : null;
      const partialURL = new URL(url.href);
      partialURL.searchParams.set('partial', 'list');
      try {
        const response = await fetch(partialURL, {
          headers: { 'X-Requested-With': 'fetch' }
        });
        if (!response.ok) {
          throw new Error('list update failed: ' + response.status);
        }
        const html = await response.text();
        if (updateID !== listUpdateID) return;
        card.outerHTML = html;
        updateBulkSelection(document.querySelector('[data-list-card]'));
        if (restoreSearchFocus) {
          const nextSearch = document.querySelector('[data-list-search]');
          if (nextSearch) {
            nextSearch.focus();
            nextSearch.setSelectionRange(selectionStart, selectionEnd);
          }
        }
        window.history.replaceState(null, '', cleanListURL(url));
      } catch (err) {
        console.error(err);
        window.location.href = cleanListURL(url).href;
      }
    }

    let listSearchTimer = null;
    document.addEventListener('input', function (event) {
      if (!event.target.matches('[data-list-search]')) return;
      clearTimeout(listSearchTimer);
      listSearchTimer = setTimeout(function () {
        replaceListCard(listURLFromForm(event.target.form));
      }, 250);
    });

    document.addEventListener('submit', function (event) {
      const form = event.target.closest('[data-list-search-form]');
      if (!form) return;
      event.preventDefault();
      replaceListCard(listURLFromForm(form));
    });

    document.addEventListener('click', function (event) {
      const link = event.target.closest('[data-list-link]');
      if (!link) return;
      event.preventDefault();
      if (link.getAttribute('aria-disabled') === 'true') return;
      replaceListCard(new URL(link.href, window.location.href));
    });

    function base64urlBytes(bytes) {
      let binary = '';
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // Public clients must use PKCE, so a static test link cannot work.
    // Generate a challenge on click and open the authorize endpoint with it.
    document.addEventListener('click', async function (event) {
      const link = event.target.closest('[data-pkce-test]');
      if (!link) return;
      event.preventDefault();
      if (!(window.crypto && window.crypto.subtle)) {
        alert('This test link needs crypto.subtle, which is only available in a secure context.');
        return;
      }
      const verifierBytes = new Uint8Array(32);
      crypto.getRandomValues(verifierBytes);
      const verifier = base64urlBytes(verifierBytes);
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
      const url = new URL(link.href, window.location.href);
      url.searchParams.set('code_challenge', base64urlBytes(new Uint8Array(digest)));
      url.searchParams.set('code_challenge_method', 'S256');
      window.open(url, '_blank', 'noreferrer');
    });

    function bulkNoun() {
      const form = document.querySelector('[data-bulk-delete-form]');
      return form && form.dataset.bulkNoun ? form.dataset.bulkNoun : 'item';
    }

    function updateBulkSelection(card) {
      const selections = Array.from(card.querySelectorAll('[data-bulk-selection]'));
      const selected = selections.filter(function (checkbox) { return checkbox.checked; });
      const selectAll = card.querySelector('[data-select-all]');
      const button = card.querySelector('[data-bulk-delete-button]');
      const count = card.querySelector('[data-bulk-selection-count]');
      if (selectAll) {
        selectAll.checked = selections.length > 0 && selected.length === selections.length;
        selectAll.indeterminate = selected.length > 0 && selected.length < selections.length;
      }
      if (button) button.disabled = selected.length === 0;
      if (count) count.textContent = String(selected.length) + ' ' + bulkNoun() + (selected.length === 1 ? '' : 's') + ' selected';
    }

    document.addEventListener('change', function (event) {
      const card = event.target.closest('[data-list-card]');
      if (!card) return;
      if (event.target.matches('[data-select-all]')) {
        for (const checkbox of card.querySelectorAll('[data-bulk-selection]')) {
          checkbox.checked = event.target.checked;
        }
      } else if (!event.target.matches('[data-bulk-selection]')) {
        return;
      }
      updateBulkSelection(card);
    });

    document.addEventListener('submit', function (event) {
      const form = event.target.closest('[data-bulk-delete-form]');
      if (!form) return;
      const noun = form.dataset.bulkNoun || 'item';
      const selected = document.querySelectorAll('[data-bulk-selection]:checked').length;
      const message = selected === 1
        ? 'Delete this ' + noun + ' from the shared directory?'
        : 'Delete ' + String(selected) + ' ' + noun + 's from the shared directory?';
      const scope = document.body.dataset.hasScimEnvironments === 'true'
        ? ' The deletion will be scheduled in every SCIM environment.'
        : ' This permanently deletes the selected ' + noun + 's.';
      if (!window.confirm(message + scope)) event.preventDefault();
    });
    const initialListCard = document.querySelector('[data-list-card]');
    if (initialListCard) updateBulkSelection(initialListCard);

    const syncForms = Array.from(document.querySelectorAll('[data-sync-form]'));
    const syncSubmits = Array.from(document.querySelectorAll('[data-sync-submit]'));
    const syncProgress = document.querySelector('[data-sync-progress]');
    const syncMessage = document.querySelector('[data-sync-message]');
    const syncCount = document.querySelector('[data-sync-count]');
	const syncFill = document.querySelector('[data-sync-fill]');
    const syncProgressBar = document.querySelector('[data-sync-progressbar]');
    const syncCurrent = document.querySelector('[data-sync-current]');
    const syncTrace = document.querySelector('[data-sync-trace]');
    const syncDetails = document.querySelector('[data-sync-details]');
    const syncDetailsOpenButtons = Array.from(document.querySelectorAll('[data-sync-details-open]'));
    const syncDetailsCloseButtons = Array.from(document.querySelectorAll('[data-sync-details-close]'));
    const syncModalProgress = document.querySelector('[data-sync-modal-progress]');
    const syncModalMessage = document.querySelector('[data-sync-modal-message]');
    const syncModalCount = document.querySelector('[data-sync-modal-count]');
    const syncModalFill = document.querySelector('[data-sync-modal-fill]');
    const syncModalProgressBar = document.querySelector('[data-sync-modal-progressbar]');
    const syncModalTrace = document.querySelector('[data-sync-modal-trace]');
    const syncActivityComplete = document.querySelector('[data-sync-activity-complete]');
    const syncActivityRemaining = document.querySelector('[data-sync-activity-remaining]');
    const syncActivityList = document.querySelector('[data-sync-activity-list]');
    const syncActivityEmpty = document.querySelector('[data-sync-activity-empty]');
    const syncNewEvents = document.querySelector('[data-sync-new-events]');
    const syncCancelButtons = Array.from(document.querySelectorAll('[data-sync-cancel]'));
    let syncPollTimer = null;
    let reloadWhenSyncFinishes = false;
    let syncDetailsVisible = false;
    let syncJobDone = false;
    let syncEventSequence = 0;
    let syncNewEventCount = 0;
    const syncEventRows = new Map();

    function setSyncProgressState(container, job) {
      if (!container) return;
      container.classList.remove('is-error', 'is-rate-limited', 'is-success');
      if (job.error) container.classList.add('is-error');
      if (job.rateLimited && !job.error) container.classList.add('is-rate-limited');
      if (job.done && !job.error) container.classList.add('is-success');
    }

    function setSyncProgress(job) {
      if (!syncProgress || !job) return;
      syncProgress.classList.remove('is-hidden');
      setSyncProgressState(syncProgress, job);
      setSyncProgressState(syncModalProgress, job);
      if (syncMessage) syncMessage.textContent = job.message || job.error || 'Sync running';
      if (syncCount) syncCount.textContent = String(job.processed || 0) + ' / ' + String(job.total || 0);
	  if (syncFill) syncFill.style.width = String(job.percent || 0) + '%';
	  if (syncProgressBar) syncProgressBar.setAttribute('aria-valuenow', String(job.percent || 0));
      if (syncCurrent) syncCurrent.textContent = job.current || '';
	  if (syncModalMessage) syncModalMessage.textContent = job.message || job.error || 'Sync running';
	  if (syncModalCount) syncModalCount.textContent = String(job.processed || 0) + ' / ' + String(job.total || 0);
	  if (syncModalFill) syncModalFill.style.width = String(job.percent || 0) + '%';
	  if (syncModalProgressBar) syncModalProgressBar.setAttribute('aria-valuenow', String(job.percent || 0));
	  if (syncActivityComplete) syncActivityComplete.textContent = String(job.processed || 0) + ' completed';
	  if (syncActivityRemaining) {
		const remaining = Math.max((job.total || 0) - (job.processed || 0), 0);
		syncActivityRemaining.textContent = String(remaining) + ' remaining';
	  }
	  if (syncTrace) syncTrace.classList.toggle('is-hidden', !job.traceAvailable);
	  if (syncModalTrace) syncModalTrace.classList.toggle('is-hidden', !job.traceAvailable);
	  for (const button of syncDetailsOpenButtons) button.classList.remove('is-hidden');
	  for (const button of syncCancelButtons) {
		button.classList.toggle('is-hidden', !job.running);
		button.disabled = false;
	  }
		for (const button of syncSubmits) button.disabled = Boolean(job.running);
		for (const button of document.querySelectorAll('form[method="post"] button[type="submit"]')) {
		  if (!syncSubmits.includes(button)) button.disabled = Boolean(job.running);
		}
      syncJobDone = Boolean(job.done);
    }

    function syncOperationTitle(event) {
      const verbs = { create: 'Create', update: 'Update', delete: 'Delete', check: 'Check' };
      const verb = verbs[event.operation] || event.operation || 'Process';
      const resource = event.resourceType || 'resource';
      return verb + ' ' + resource + ': ' + event.label;
    }

    function syncPhaseLabel(phase) {
      const labels = { running: 'In progress', done: 'Done', failed: 'Failed', waiting: 'Waiting' };
      return labels[phase] || phase;
    }

    function activityListAtBottom() {
      if (!syncActivityList) return true;
      return syncActivityList.scrollHeight - syncActivityList.scrollTop - syncActivityList.clientHeight < 24;
    }

    function updateNewEventsButton() {
      if (!syncNewEvents) return;
      syncNewEvents.classList.toggle('is-hidden', syncNewEventCount === 0);
      syncNewEvents.textContent = syncNewEventCount === 1 ? '1 new update' : String(syncNewEventCount) + ' new updates';
    }

    function renderSyncEvents(events) {
      if (!syncActivityList || !Array.isArray(events) || events.length === 0) return;
      const followActivity = activityListAtBottom();
      for (const event of events) {
        syncEventSequence = Math.max(syncEventSequence, event.sequence || 0);
        let row = syncEventRows.get(event.id);
        if (!row) {
          row = document.createElement('div');
          row.className = 'sync-activity-row';
          row.dataset.syncEvent = event.id;

          const title = document.createElement('div');
          title.className = 'sync-activity-title';
          row.appendChild(title);

          const state = document.createElement('div');
          state.className = 'sync-activity-state';
          row.appendChild(state);

          const detail = document.createElement('div');
          detail.className = 'sync-activity-detail';
          row.appendChild(detail);

          syncEventRows.set(event.id, row);
          syncActivityList.appendChild(row);
        }

        row.classList.remove('is-running', 'is-done', 'is-failed', 'is-waiting');
        row.classList.add('is-' + event.phase);
        row.querySelector('.sync-activity-title').textContent = syncOperationTitle(event);
        row.querySelector('.sync-activity-state').textContent = syncPhaseLabel(event.phase);
        const detail = row.querySelector('.sync-activity-detail');
        detail.textContent = event.detail || '';
        detail.hidden = !event.detail;
      }

      if (syncActivityEmpty) syncActivityEmpty.hidden = syncEventRows.size > 0;
      if (followActivity) {
        syncActivityList.scrollTop = syncActivityList.scrollHeight;
        syncNewEventCount = 0;
      } else if (syncDetailsVisible) {
        syncNewEventCount += events.length;
      }
      updateNewEventsButton();
    }

    function resetSyncActivity() {
      syncEventSequence = 0;
      syncNewEventCount = 0;
      for (const row of syncEventRows.values()) row.remove();
      syncEventRows.clear();
      if (syncActivityEmpty) syncActivityEmpty.hidden = false;
      updateNewEventsButton();
    }

    function openSyncDetails(refresh) {
      if (!syncDetails) return;
      syncDetails.classList.remove('is-hidden');
      syncDetails.setAttribute('aria-hidden', 'false');
      syncDetailsVisible = true;
	  for (const region of document.querySelectorAll('.topbar, .app, .footer')) {
		region.setAttribute('inert', '');
		region.setAttribute('aria-hidden', 'true');
	  }
      const close = syncDetails.querySelector('[data-sync-details-close]');
      if (close) close.focus();
      if (refresh !== false && !syncPollTimer) pollSyncStatus();
    }

    function closeSyncDetails() {
      if (!syncDetails || !syncDetailsVisible) return;
      syncDetails.classList.add('is-hidden');
      syncDetails.setAttribute('aria-hidden', 'true');
      syncDetailsVisible = false;
	  for (const region of document.querySelectorAll('.topbar, .app, .footer')) {
		region.removeAttribute('inert');
		region.removeAttribute('aria-hidden');
	  }
      if (reloadWhenSyncFinishes && syncJobDone) {
        window.location.reload();
        return;
      }
      const returnFocus = syncDetailsOpenButtons.find(button => !button.classList.contains('is-hidden')) || syncSubmits[0];
      if (returnFocus) returnFocus.focus();
    }

    function syncStatusURL() {
      const statusURL = new URL('/sync/status', window.location.href);
      statusURL.searchParams.set('environment', document.body.dataset.environmentId || '');
      statusURL.searchParams.set('after', String(syncEventSequence));
      return statusURL;
    }

    async function pollSyncStatus() {
      syncPollTimer = null;
      try {
        const response = await fetch(syncStatusURL(), {
          headers: { 'Accept': 'application/json' }
        });
        if (!response.ok) {
          throw new Error('sync status failed: ' + response.status);
        }
        const job = await response.json();
        if (!job) return;
        setSyncProgress(job);
        renderSyncEvents(job.events);
        if (job && job.running) {
          syncPollTimer = setTimeout(pollSyncStatus, 750);
          return;
        }
        syncPollTimer = null;
        if (job && job.done && reloadWhenSyncFinishes) {
          if (!syncDetailsVisible) window.location.reload();
        }
      } catch (err) {
        console.error(err);
        if (syncMessage) syncMessage.textContent = err.message;
        if (syncProgress) syncProgress.classList.add('is-error');
        for (const button of syncSubmits) button.disabled = false;
      }
    }

    for (const form of syncForms) {
      form.addEventListener('submit', async function (event) {
        event.preventDefault();
        if (syncPollTimer) clearTimeout(syncPollTimer);
        syncPollTimer = null;
        reloadWhenSyncFinishes = true;
        syncJobDone = false;
        resetSyncActivity();
        openSyncDetails(false);
        for (const button of syncSubmits) button.disabled = true;
        const kind = form.dataset.syncKind || 'sync';
        setSyncProgress({ running: true, message: 'Starting ' + kind + ' for ' + (document.body.dataset.environmentName || 'the active environment'), processed: 0, total: 0, percent: 0 });
        try {
          const response = await fetch(form.action, {
            method: 'POST',
            body: new FormData(form),
            headers: {
              'Accept': 'application/json',
              'X-Requested-With': 'fetch'
            }
          });
          const job = await response.json();
          if (!response.ok) {
            throw new Error(job.error || job.message || kind + ' could not start');
          }
          setSyncProgress(job);
          renderSyncEvents(job.events);
          syncPollTimer = setTimeout(pollSyncStatus, 300);
        } catch (err) {
          console.error(err);
          setSyncProgress({ done: true, error: err.message, message: err.message, percent: 100 });
        }
      });
    }

    for (const button of syncCancelButtons) {
      button.addEventListener('click', async function () {
		for (const candidate of syncCancelButtons) candidate.disabled = true;
		const form = new FormData();
		form.set('environment', document.body.dataset.environmentId || '');
		try {
		  const response = await fetch('/sync/cancel', {
			method: 'POST',
			body: form,
			headers: { 'Accept': 'application/json', 'X-Requested-With': 'fetch' }
		  });
		  const result = await response.json();
		  if (!response.ok) throw new Error(result.error || 'sync could not be cancelled');
		  if (syncMessage) syncMessage.textContent = result.message;
		  if (syncModalMessage) syncModalMessage.textContent = result.message;
		  if (!syncPollTimer) syncPollTimer = setTimeout(pollSyncStatus, 100);
		} catch (err) {
		  console.error(err);
		  for (const candidate of syncCancelButtons) candidate.disabled = false;
		  if (syncMessage) syncMessage.textContent = err.message;
		}
      });
    }

    if (syncProgress && syncProgress.dataset.syncActive === 'true') {
      reloadWhenSyncFinishes = true;
      pollSyncStatus();
    }

    for (const button of syncDetailsOpenButtons) {
      button.addEventListener('click', openSyncDetails);
    }
    for (const button of syncDetailsCloseButtons) {
      button.addEventListener('click', closeSyncDetails);
    }
    if (syncDetails) {
      let syncMouseDownOnBackdrop = false;
      syncDetails.addEventListener('mousedown', function (event) {
        syncMouseDownOnBackdrop = event.target === syncDetails;
      });
      syncDetails.addEventListener('mouseup', function (event) {
        if (syncMouseDownOnBackdrop && event.target === syncDetails) closeSyncDetails();
        syncMouseDownOnBackdrop = false;
      });
    }
    if (syncNewEvents) {
      syncNewEvents.addEventListener('click', function () {
        if (syncActivityList) syncActivityList.scrollTop = syncActivityList.scrollHeight;
        syncNewEventCount = 0;
        updateNewEventsButton();
      });
    }
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && syncDetailsVisible) closeSyncDetails();
    });
