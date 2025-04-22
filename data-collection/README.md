# Dependency Counter

This folder holds various scripts used to count the number of dependencies in a given codebase. This is used to demonstrate the effects of dependency supply chain attacks.

`*deps-counts.csv` shows how the number of dependencies increases with more dependencies installed. This looks at the package-lock.json or uses a tool like pipdeptree. This was done by installing the top 20 packages from npm listed [here](https://gist.github.com/anvaka/8e8fa57c7ee1350e3491)
    - In reality, the number of dependencies is much larger. This is because the top 20 packages are usually low level packages that many higher level modules rely on (e.g. request).
