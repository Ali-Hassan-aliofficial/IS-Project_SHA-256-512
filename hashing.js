Module.onRuntimeInitialized = function () {
    document.getElementById("hashButton").onclick = function () {
        const input = document.getElementById("input").value;
        const algorithm = document.querySelector('input[name="hashingAlgorithm"]:checked').value;
    
        if (!input) {
            alert("Please enter text to hash!");
            return;
        }
    
        // Allocate memory for the input string
        const inputPtr = Module.allocateUTF8(input);
        
        // Compute the hash and retrieve additional information
        const hashDetailsPtr = algorithm === "sha256"
            ? Module._compute_sha256(inputPtr)
            : Module._compute_sha512(inputPtr);
        
        // Convert the returned C string to a JavaScript string
        const hashDetails = Module.UTF8ToString(hashDetailsPtr);
    
        // Display the result
        document.getElementById("result").innerText = `Results:\n${hashDetails}`;
    };
    
};
