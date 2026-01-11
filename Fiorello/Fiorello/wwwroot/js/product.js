document.addEventListener("DOMContentLoaded", function () {
    const deleteButtons = document.querySelectorAll(".delete-photo");

    if (deleteButtons.length) {
        deleteButtons.forEach(btn => {
            btn.addEventListener("click", function () {
                const id = this.getAttribute("data-id");
                const tokenInput = document.querySelector('input[name="__RequestVerificationToken"]');
                if (!tokenInput) {
                    console.error("Anti-forgery token tapılmadı");
                    return;
                }
                const token = tokenInput.value;

                if (!confirm("Bu sekli silmək istediyinizden eminsiz?")) return;

                const formData = new FormData();
                formData.append("id", id);

                fetch('/Admin/Product/DeleteAdditionalImage', {
                    method: 'POST',
                    headers: {
                        'RequestVerificationToken': token
                    },
                    body: formData
                })
                    .then(res => {
                        if (!res.ok) throw new Error("Server xetası!");
                        return res.json();
                    })
                    .then(data => {
                        if (data.success) {
                            const photoElement = document.getElementById("photo-" + id);
                            if (photoElement) {
                                photoElement.remove();
                            }
                        } else {
                            alert(data.message || "Xeta bas verdi!");
                        }
                    })
                    .catch(err => {
                        console.error("Fetch xetası:", err);
                        alert("Sistem xetası bas verdi.");
                    });
            });
        });
    }
});