class LibraryLoader {
    constructor() {
        this.loadedLibs = new Set();
    }

    async loadScript(url) {
        return new Promise((resolve, reject) => {
            if (this.loadedLibs.has(url)) {
                resolve();
                return;
            }

            const script = document.createElement('script');
            script.src = url;
            
            script.onload = () => {
                this.loadedLibs.add(url);
                resolve();
            };
            
            script.onerror = (error) => {
                reject(new Error(`Failed to load library: ${url}`));
            };
            
            document.head.appendChild(script);
        });
    }

    async loadLibraries(libraries) {
        console.log("Loading libraries...");
        
        for (const lib of libraries) {
            try {
                const url = browser.runtime.getURL(`libs/${lib}`);
                await this.loadScript(url);
                console.log(`Library loaded: ${lib}`);
            } catch (error) {
                console.error(`Error loading ${lib}:`, error);
                throw error;
            }
        }
        
        return true;
    }
}

export async function loadlibs() {
    const loader = new LibraryLoader();
    const requiredLibs = [
        { file: 'noble-curves.js', symbol: 'nobleCurves' },
        { file: 'cbor.js', symbol: 'CBOR' }
    ];
    
    try {
        await loader.loadLibraries(requiredLibs.map(lib => lib.file));

        for (const lib of requiredLibs) {
            if (!(lib.symbol in window)) {
                throw new Error(`Library symbol ${lib.symbol} not found in window object after loading ${lib.file}`);
            }
        }
    } catch (error) {
        console.error('Failed to load libraries:', error);
        throw error;
    }
}