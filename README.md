# Substation Sentinel: Network Traffic Analysis and Cybersecurity for Substation Automation

## Overview

**Substation Sentinel** is a command-line tool developed for analyzing network traffic in digital substations, focusing on GOOSE (Generic Object-Oriented Substation Event) and Sampled Values (SV) protocols within IEC 61850 networks. This tool is designed to help researchers, network engineers, and cybersecurity professionals assess the performance, vulnerabilities, and security of substation automation systems.

The tool offers real-time and offline packet analysis, message filtering, basic correlation, mathematical analysis, and attack simulations. It supports the diagnosis of system behavior, the identification of interdependencies among devices, and the assessment of potential cyberattacks in substation communication protocols.

## Key Features

- **Message Filtering**: Filter network messages based on identifiers like GOID and SVID for GOOSE and SV protocols.
- **Traffic Analysis**: Analyze network packets in real-time or offline for detailed insights into substation operations.
- **Cyberattack Simulations**: Simulate message replay, value modification, and other attack scenarios to assess the security of the network.
- **Correlation Analysis**: Identify device interdependencies and their impact on network behavior.
- **Detailed Protocol Decoding**: Decode GOOSE and SV messages, including payload analysis using ASN.1 decoding and IEEE 754 floating-point conversion.
- **Wireshark Integration**: Capture and visualize modified packets for troubleshooting and educational purposes.

## Background

Substations are critical components of modern power systems, facilitating voltage transformation, system protection, power flow control, and real-time monitoring. Traditionally, these functions were carried out by manual operations and electromechanical devices, but advancements in substation automation have led to more efficient, reliable, and secure operations. The adoption of IEC 61850 has revolutionized substation communications, providing interoperability, scalability, and real-time data exchange.

This tool builds on these technological advancements and aims to enhance the security of substation automation systems by identifying vulnerabilities in communication protocols. With the increasing digitization of substations, cybersecurity is a growing concern, and Substation Sentinel helps address this by simulating and analyzing potential attacks.

## Tools & Technologies

- **Python**: The core programming language for the tool, leveraging libraries such as Scapy, PyASN1, and Pandas for network traffic analysis and protocol manipulation.
- **Scapy**: A powerful tool for crafting and inspecting network packets.
- **Wireshark**: Used for packet capture and visualization, complementing the analysis capabilities of Substation Sentinel.
- **GooseStalker**: Extends the tool's capabilities to analyze and test vulnerabilities in the GOOSE protocol.

## Use Cases

- **Cybersecurity Research**: Simulate attacks (e.g., message replay and modification) to evaluate the security of substation networks.
- **Protocol Development**: Analyze and debug GOOSE and SV protocols within IEC 61850 networks.
- **Network Diagnostics**: Identify issues in substation automation systems by analyzing network traffic and interdependencies.
- **Education & Training**: Use the tool to visualize network communication, teach protocol analysis, and practice cybersecurity techniques.

## Usage

For detailed usage instructions, including command-line options and examples, please refer to **Chapter 7** of the author's thesis.

## Contributing

Contributions are welcome! Please feel free to fork this repository, submit pull requests, and open issues for improvements or new features.

## License

This project is licensed under the MIT License

## Acknowledgements

This tool builds upon the concepts presented in the author's thesis on substation automation and cybersecurity. The thesis explores the role of IEC 61850 in modernizing substations, the importance of real-time data exchange, and the emerging cybersecurity challenges faced by utilities.

## Conclusion

Substation Sentinel empowers users to better understand and secure substation automation networks by providing detailed traffic analysis and simulating potential cyberattacks. The tool plays a crucial role in enhancing the reliability and security of critical infrastructure in modern power systems.

For more details, please refer to the full thesis or check out the [documentation](https://github.com/Ralle001/Substation-Sentinel/blob/main/Thesis.pdf).
