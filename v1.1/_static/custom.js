// Version selector — move into sidebar below logo, above search
// (same mechanism as the cryptnox-hardware-wallet docs)
document.addEventListener('DOMContentLoaded', function () {
    var container = document.getElementById('version-selector-container');
    if (!container) return;
    var searchArea = document.querySelector('.wy-side-nav-search');
    var searchForm = searchArea && searchArea.querySelector('[role="search"]');
    if (searchArea && searchForm) {
        searchArea.insertBefore(container, searchForm);
        container.style.display = 'block';
    }
    var btn = document.getElementById('version-dropdown-btn');
    var list = document.getElementById('version-dropdown-list');
    if (btn && list) {
        // Move list to body so sidebar overflow:hidden doesn't clip it
        document.body.appendChild(list);

        function positionList() {
            var rect = btn.getBoundingClientRect();
            list.style.position = 'fixed';
            list.style.top = (rect.bottom + 2) + 'px';
            list.style.left = rect.left + 'px';
            list.style.width = rect.width + 'px';
        }

        btn.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            var open = list.classList.toggle('open');
            btn.setAttribute('aria-expanded', open);
            if (open) positionList();
        });

        list.querySelectorAll('.version-option').forEach(function (option) {
            option.addEventListener('click', function (e) {
                e.preventDefault();
                e.stopPropagation();
                var url = this.getAttribute('data-url');
                if (url) window.location.href = url;
            });
        });

        document.addEventListener('click', function (e) {
            if (!container.contains(e.target) && !list.contains(e.target)) {
                list.classList.remove('open');
                btn.setAttribute('aria-expanded', 'false');
            }
        });
    }
});
