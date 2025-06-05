````markdown
# subscarp

🔍 **subscarp** is a powerful subdomain enumeration script that uses multiple open-source tools to gather subdomains of a target domain efficiently.

## ⚙️ Features

- ✅ Collects subdomains using multiple tools
- ✅ Merges and deduplicates results into a single file
- ✅ Fully automated and easy to use

## 📦 Installation

```bash
git clone https://github.com/Cyb3rGh05tX/subscarp.git
cd subscarp
chmod +x subscarp.sh
````

## 🚀 Usage

```bash
./subscarp.sh example.com
```

This will enumerate subdomains for `example.com` and save the final list to a file named `example.com.txt`.

## 🛠️ Requirements

Make sure the following tools are installed and accessible in your system:

* [`assetfinder`](https://github.com/tomnomnom/assetfinder)
* [`amass`](https://github.com/owasp-amass/amass)
* [`subfinder`](https://github.com/projectdiscovery/subfinder)
* [`findomain`](https://github.com/findomain/findomain)

## 📁 Output

The results will be saved in a `.txt` file with the same name as the target domain, for example:

```
example.com.txt
```

## 🤝 Contributing

Feel free to fork this repository, make improvements, and submit a Pull Request!

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```
