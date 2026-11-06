    const search = document.querySelector('[data-user-search]');
    const options = Array.from(document.querySelectorAll('[data-user-option]'));
    const matchCount = document.querySelector('[data-match-count]');
    const noMatches = document.querySelector('[data-no-matches]');
    const continueButton = document.querySelector('[data-continue]');
    function filterUsers() {
      const terms = search.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
      let visible = 0;
      for (const option of options) {
        const value = option.dataset.search.toLocaleLowerCase();
        const matches = terms.every(function (term) { return value.includes(term); });
        option.hidden = !matches;
        const radio = option.querySelector('input[type="radio"]');
        if (radio) radio.disabled = !matches;
        if (matches) {
          visible++;
        } else {
          if (radio) radio.checked = false;
        }
      }
      matchCount.textContent = String(visible) + (visible === 1 ? ' user' : ' users');
      noMatches.hidden = visible !== 0;
      continueButton.disabled = visible === 0;
    }
    search.addEventListener('input', filterUsers);
    filterUsers();
