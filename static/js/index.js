document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', function() {
    const targetId = this.getAttribute('data-target');
    const targetSection = document.getElementById(targetId);

    // Scroll to the target section
    targetSection.scrollIntoView({
      behavior: 'smooth' // Adds smooth scrolling
    });
  });
});
