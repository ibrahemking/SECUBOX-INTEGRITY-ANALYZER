// Report data
const reports = [
    {
        name: "Code Quality Report 1",
        description: "Detailed analysis of the static code with identified vulnerabilities and suggestions for improvements.",
        riskLevel: "High",
        date: "2024-11-10"
      },
      {
        name: "Vulnerability Detection Report",
        description: "Inspection of coding practices, style issues, and potential security risks in the codebase.",
        riskLevel: "Medium",
        date: "2024-11-18"
      },
      {
        name: "Code Security Review Report",
        description: "Thorough review of source code to detect syntax errors, unused variables, and potential performance bottlenecks.",
        riskLevel: "Low",
        date: "2024-11-25"
      },
      {
        name: "Static Code Review Report",
        description: "Code quality assessment with a focus on refactoring recommendations and reducing technical debt.",
        riskLevel: "Medium",
        date: "2024-12-02"
      },
      {
        name: "Performance & Security Code Scan",
        description: "Comprehensive review of the codebase with detailed findings on accessibility issues and security flaws.",
        riskLevel: "High",
        date: "2024-12-05"
      }
  ];
  
  // Function to display the reports inside cards
  function displayReports() {
    const projectsList = document.getElementById('projectsList');
    projectsList.innerHTML = ''; // Clear previous content if any
  
    reports.forEach(report => {
      // Create the main card element
      const card = document.createElement('div');
      card.className = 'card';
  
      // Create the inner container for the card
      const card2 = document.createElement('div');
      card2.className = 'card2';
  
      // Add content inside the card
      card2.innerHTML = `
        <h3>${report.name}</h3>
         <p><strong>Description:</strong></p> 
        <p> ${report.description}</p>
        <p><strong>Risk Level:</strong> ${report.riskLevel}</p>
        <p><strong>Scan Date:</strong> ${new Date(report.date).toLocaleDateString()}</p>
      `;
  
      // Append the inner container to the card
      card.appendChild(card2);
  
      // Append the card to the projects list
      projectsList.appendChild(card);
    });
  }
  
  // Call the function when the page loads
  window.onload = displayReports;
  