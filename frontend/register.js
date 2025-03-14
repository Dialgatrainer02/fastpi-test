document.getElementById("registerForm").addEventListener("submit", async function (e) {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const messageBox = document.getElementById("message");
    jsonData = JSON.parse(`{"name": "${username}", "email": "${email}", "password": "${password}"}`)
    // console.log(jsonData)

    try {
        const response = await fetch("http://localhost:8000/user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: jsonData
        });

        if (!response.ok) {
            throw new Error("Invalid username or password");
        }

        const data = await response.json();
        messageBox.style.color = "green";
        messageBox.textContent = "register successful! Now log in";
        setTimeout(() => window.location.href = "index.html", 1000);
    } catch (error) {
        messageBox.textContent = error.message;
    }
});
