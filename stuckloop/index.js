// Get the form element
const form = document.querySelector("form");
const loader = document.getElementById("loader");
const outputBox = document.getElementById("outputbox");

// Listen for the form's submit event
form.addEventListener("submit", function(event) {
    event.preventDefault(); // Prevent the default form submission behavior (page reload)
    loader.style.display = "block"; // Show the loader while the request is processed

    // Create a new FormData object to hold the form data
    const formData = new FormData(form);

    // Send the form data using the Fetch API
    fetch('index.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text()) // Expecting a response in text format
    .then(data => {
        loader.style.display = "none"; // Hide the loader once the request is completed
        outputBox.innerHTML = data; // Display the response in the output box
    })
    .catch(error => {
        loader.style.display = "none"; // Hide the loader in case of an error
        outputBox.innerHTML = "Error: " + error.message; // Display the error message in the output box
    });
});
