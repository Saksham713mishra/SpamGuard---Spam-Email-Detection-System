document.addEventListener('DOMContentLoaded', function () {
    const wrapper = document.getElementById('wrapper');
    const sidebar = document.getElementById('sidebar-wrapper');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const mobileBreakpoint = 992;

    function isMobile() {
        return window.innerWidth <= mobileBreakpoint;
    }

    function closeSidebar() {
        if (wrapper) {
            wrapper.classList.remove('toggled');
        }
    }

    function toggleSidebar() {
        if (wrapper) {
            wrapper.classList.toggle('toggled');
        }
    }

    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function (event) {
            event.preventDefault();
            toggleSidebar();
        });
    }

    document.addEventListener('click', function (event) {
        if (!isMobile() || !wrapper || !sidebar || !sidebarToggle) {
            return;
        }

        const clickedInsideSidebar = sidebar.contains(event.target);
        const clickedToggle = sidebarToggle.contains(event.target);

        if (!clickedInsideSidebar && !clickedToggle && wrapper.classList.contains('toggled')) {
            closeSidebar();
        }
    });

    document.addEventListener('keydown', function (event) {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'b') {
            event.preventDefault();
            toggleSidebar();
        }

        if (event.key === 'Escape' && isMobile()) {
            closeSidebar();
        }
    });

    window.addEventListener('resize', function () {
        if (!isMobile()) {
            closeSidebar();
        }
    });

    const revealElements = document.querySelectorAll('.reveal');

    if ('IntersectionObserver' in window) {
        const revealObserver = new IntersectionObserver(
            function (entries, observer) {
                entries.forEach(function (entry) {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('is-visible');
                        observer.unobserve(entry.target);
                    }
                });
            },
            {
                threshold: 0.15,
                rootMargin: '0px 0px -40px 0px'
            }
        );

        revealElements.forEach(function (element) {
            revealObserver.observe(element);
        });
    } else {
        revealElements.forEach(function (element) {
            element.classList.add('is-visible');
        });
    }
});
