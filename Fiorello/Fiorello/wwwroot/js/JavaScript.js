let loadMore = document.querySelector(".load-more");

loadMore.addEventListener("click", function () {
    let htmlProductCount = document.querySelectorAll(".load-products .product").length;
    let dbProductCount = document.querySelector(".load-products .product-count").value;

    fetch(`Home/LoadMore?skip=${htmlProductCount}`)
        .then(response => response.text())
        .then(response => {
            let parent = document.querySelector(".load-products");
            parent.innerHTML += response;

            htmlProductCount = document.querySelectorAll(".load-products .product").length;

            if (htmlProductCount == dbProductCount) {
                this.style.display = "none";
            }
        });
});