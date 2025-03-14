document.getElementById("loginForm").addEventListener("submit", async function (e) {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const messageBox = document.getElementById("message");

    const formData = new URLSearchParams();
    formData.append("grant_type", "password");
    formData.append("username", username);
    formData.append("password", password);

    try {
        const response = await fetch("http://localhost:8000/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData
        });

        if (!response.ok) {
            throw new Error("Invalid username or password");
        }

        const data = await response.json();
        localStorage.setItem("access_token", data.access_token);
        messageBox.style.color = "green";
        messageBox.textContent = "Login successful!";
        setTimeout(() => window.location.href = "dashboard.html", 1000);
    } catch (error) {
        messageBox.textContent = error.message;
    }
});
