document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".add-to-basket").forEach(btn => {
        btn.addEventListener("click", function () {
            const productId = this.getAttribute("data-id");

            fetch(`/Basket/Add?id=${productId}`, {
                method: "POST"
            })
                .then(res => res.json())
                .then(data => {
                    const basketCountElem = document.getElementById("basketCount");
                    if (basketCountElem) {
                        basketCountElem.innerText = data.count;
                    }
                    alert("Product added to basket");
                })
                .catch(err => console.error(err));
        });
    });
});
