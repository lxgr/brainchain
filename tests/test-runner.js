export async function runTests(testSuite) {
    const results = document.getElementById('test-results');
    
    for (const [groupName, tests] of Object.entries(testSuite)) {
        const groupDiv = document.createElement('div');
        groupDiv.className = 'test-group';
        groupDiv.innerHTML = `<h3>${groupName}</h3>`;
        results.appendChild(groupDiv);
        
        for (const [testName, testFn] of Object.entries(tests)) {
            const resultDiv = document.createElement('div');
            try {
                await testFn();
                resultDiv.className = 'test-pass';
                resultDiv.textContent = `✓ ${testName}`;
            } catch (error) {
                resultDiv.className = 'test-fail';
                resultDiv.textContent = `✗ ${testName}: ${error.message}`;
                console.error(`Test failed: ${testName}`, error);
            }
            groupDiv.appendChild(resultDiv);
        }
    }
}

export function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

export function assertEquals(actual, expected, message = '') {
    if (actual !== expected) {
        throw new Error(
            `${message} Expected ${JSON.stringify(expected)} but got ${JSON.stringify(actual)}`
        );
    }
}

export function assertArrayEquals(actual, expected, message = '') {
    if (actual.length !== expected.length) {
        throw new Error(
            `${message} Arrays have different lengths. Expected ${expected.length} but got ${actual.length}`
        );
    }
    
    for (let i = 0; i < actual.length; i++) {
        if (actual[i] !== expected[i]) {
            throw new Error(
                `${message} Arrays differ at index ${i}. Expected ${expected[i]} but got ${actual[i]}`
            );
        }
    }
}