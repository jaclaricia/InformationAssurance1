import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;

public class TrustPay extends JFrame {
    private JTextField nameField, salaryField;
    private JTextArea displayArea;
    private JButton addButton, deleteButton, viewButton, loginButton;
    private JPanel loginPanel, payrollPanel;
    private boolean isLoggedIn = false; // R001: No session enforcement or role-based access control

    public TrustPay() {
        setTitle("TrustPay - Payroll System");
        setSize(500, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        loginPanel = new JPanel(new GridLayout(3, 2, 10, 10));
        loginPanel.setBorder(BorderFactory.createTitledBorder("Login"));
        JTextField userField = new JTextField();
        JPasswordField passField = new JPasswordField();
        loginButton = new JButton("Login");
        loginPanel.add(new JLabel("Username:"));
        loginPanel.add(userField);
        loginPanel.add(new JLabel("Password:"));
        loginPanel.add(passField);
        loginPanel.add(new JLabel());
        loginPanel.add(loginButton);

        payrollPanel = new JPanel();
        payrollPanel.setLayout(new BorderLayout());
        JPanel inputPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Payroll Entry"));
        nameField = new JTextField();
        salaryField = new JTextField();
        inputPanel.add(new JLabel("Employee Name:"));
        inputPanel.add(nameField);
        inputPanel.add(new JLabel("Salary:"));
        inputPanel.add(salaryField);

        JPanel buttonPanel = new JPanel();
        addButton = new JButton("Add Entry");
        deleteButton = new JButton("Delete Payroll File");
        viewButton = new JButton("View Payroll Records");
        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(viewButton);

        displayArea = new JTextArea();
        JScrollPane scrollPane = new JScrollPane(displayArea);

        payrollPanel.add(inputPanel, BorderLayout.NORTH);
        payrollPanel.add(buttonPanel, BorderLayout.CENTER);
        payrollPanel.add(scrollPane, BorderLayout.SOUTH);

        add(loginPanel);

        loginButton.addActionListener(e -> {
            String user = userField.getText();
            String pass = new String(passField.getPassword());
            if (user.equals("admin") && pass.equals("admin123")) { // R002: Hardcoded plaintext credentials
                isLoggedIn = true;
                setContentPane(payrollPanel);
                revalidate();
            } else {
                JOptionPane.showMessageDialog(this, "Invalid credentials");
            }
        });

        addButton.addActionListener(e -> {
            try (FileWriter fw = new FileWriter("payroll.csv", true)) {
                String entry = nameField.getText() + "," + salaryField.getText() + "\n";
                fw.write(entry); // R003: Unsanitized input (CSV injection possible), R006: No input validation
                displayArea.append("Added: " + entry);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex.toString()); // R007: Verbose error messages
            }
        });

        viewButton.addActionListener(e -> {
            displayArea.setText("");
            try (Scanner sc = new Scanner(new File("payroll.csv"))) {
                while (sc.hasNextLine()) {
                    displayArea.append(sc.nextLine() + "\n");
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex.toString()); // R007: Verbose error messages
            }
        });

        deleteButton.addActionListener(e -> {
            File f = new File("payroll.csv");
            if (f.exists()) {
                f.delete(); // R005: Unrestricted file deletion without confirmation or access control
                displayArea.setText("Payroll file deleted.\n");
            }
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new TrustPayVulnerable().setVisible(true));
    }
}

// Remediation Suggestions:
// R001: Implement session and role-based access control. Use a proper login system and restrict access to components based on user roles.
// R002: Store passwords securely using hashing algorithms like SHA-256 with salt, and never hardcode credentials in code.
// R003: Sanitize inputs before writing to CSV (e.g., escape characters like =, +, @) to prevent CSV injection.
// R004: Add logging mechanisms to monitor login attempts and modifications to files for auditing and security.
// R005: Confirm deletion actions with a prompt (e.g., JOptionPane confirmation) and restrict it to admin users only.
// R006: Validate input fields using regex (e.g., names should contain only letters, salary should be numeric).
// R007: Replace detailed error messages with user-friendly alerts and log technical details to a file for internal debugging.
