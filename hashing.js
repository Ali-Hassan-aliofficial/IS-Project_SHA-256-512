// Module.onRuntimeInitialized = function () {
//     document.getElementById("hashButton").onclick = function () {
//         const input = document.getElementById("input").value;
//         const algorithm = document.querySelector('input[name="hashingAlgorithm"]:checked').value;

//         if (!input) {
//             alert("Please enter text to hash!");
//             return;
//         }

//         const inputPtr = Module.allocateUTF8(input);
//         const hashPtr = algorithm === "sha256" 
//             ? Module._compute_sha256(inputPtr) 
//             : Module._compute_sha512(inputPtr);
        
//         const hash = Module.UTF8ToString(hashPtr);
//         document.getElementById("result").innerText = `${algorithm.toUpperCase()} Hash: ${hash}`;
//     };
// };

Module.onRuntimeInitialized = function () {
    document.getElementById("hashButton").onclick = function () {
        const input = document.getElementById("input").value;
        const algorithm = document.querySelector('input[name="hashingAlgorithm"]:checked').value;

        if (!input) {
            alert("Please enter text to hash!");
            return;
        }

        const inputPtr = Module.allocateUTF8(input);
        const hashPtr = algorithm === "sha256" 
            ? Module._compute_sha256(inputPtr) 
            : Module._compute_sha512(inputPtr);
        
        const hash = Module.UTF8ToString(hashPtr);
        document.getElementById("result").innerText = `${algorithm.toUpperCase()} Hash: ${hash}`;
    };
};
