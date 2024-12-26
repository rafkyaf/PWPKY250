// Example JavaScript to enhance user experience

document.addEventListener("DOMContentLoaded", function () {
  // Add event listeners or any other JavaScript code here

  // Example: Confirm before deleting a user
  const deleteForms = document.querySelectorAll('form[action*="delete"]');
  deleteForms.forEach((form) => {
    form.addEventListener("submit", function (event) {
      const confirmed = confirm("Are you sure you want to delete this user?");
      if (!confirmed) {
        event.preventDefault();
      }
    });
  });
});
