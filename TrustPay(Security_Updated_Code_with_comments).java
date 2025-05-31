import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.*;

public class TrustPaySecure extends JFrame {
    // Externalized configuration and log file for credentials and activity tracking
    private static final String CONFIG_FILE = "config.txt";          // R002, R0010
    private static final String LOG_FILE = "audit.log";              // R004
    private static final String PAYROLL_FILE = "payroll.csv";        // R008
    private static final String BACKUP_DIR = "backups/";             // R009
    private static final String ENCRYPTION_KEY = "1234567890abcdef"; // R008 - AES Key

    private JTextField nameField, salaryField;
    private JTextArea displayArea;
    private JButton addButton, deleteButton, viewButton, loginButton;
    private JPanel loginPanel, payrollPanel;
    private boolean isLoggedIn = false;  // R001 - Session control added
    private String currentUser = null;

    private Logger logger;

    public TrustPaySecure() {
        setTitle("TrustPay - Secure Payroll System");
        setSize(600, 450);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        logger = Logger.getLogger("AuditLog");

        // R004: Log user actions like login, data access, and deletion
        try {
            FileHandler handler = new FileHandler(LOG_FILE, true);
            logger.addHandler(handler);
            logger.setUseParentHandlers(false);
            handler.setFormatter(new SimpleFormatter());
        } catch (IOException e) {
            showError("Logging error", e); // R007: Show user-friendly error only
        }

        // --- UI Components ---
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

        payrollPanel = new JPanel(new BorderLayout());
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
        displayArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(displayArea);

        payrollPanel.add(inputPanel, BorderLayout.NORTH);
        payrollPanel.add(buttonPanel, BorderLayout.CENTER);
        payrollPanel.add(scrollPane, BorderLayout.SOUTH);

        add(loginPanel);

        // R001, R002, R0010: Login with session control and credential hash verification
        loginButton.addActionListener(e -> {
            try {
                String user = userField.getText();
                String pass = new String(passField.getPassword());
                if (validateLogin(user, pass)) {
                    isLoggedIn = true;
                    currentUser = user;
                    log("User logged in: " + user); // R004
                    setContentPane(payrollPanel);
                    revalidate();
                } else {
                    showMessage("Invalid credentials");
                    log("Failed login attempt: " + user); // R004
                }
            } catch (Exception ex) {
                showError("Login failed", ex); // R007
            }
        });

        // R003, R006, R008, R009: Validates input, escapes CSV injection, encrypts, and backs up data
        addButton.addActionListener(e -> {
            try {
                String name = nameField.getText().trim();
                String salary = salaryField.getText().trim();
                // R006: Input validation using regex
                if (!name.matches("[A-Za-z ]+") || !salary.matches("\\d+(\\.\\d{1,2})?")) {
                    showMessage("Invalid input format");
                    return;
                }
                // R003: Sanitize inputs to prevent CSV injection
                String record = escapeCSV(name) + "," + escapeCSV(salary);
                backupFile();                         // R009: Backup before modifying file
                writeEncryptedLine(PAYROLL_FILE, record); // R008: Write encrypted data
                displayArea.append("Added: " + record + "\n");
                log("Record added: " + record);       // R004
            } catch (Exception ex) {
                showError("Add entry failed", ex);     // R007
            }
        });

        // R008: Securely view encrypted payroll entries
        viewButton.addActionListener(e -> {
            try {
                displayArea.setText("");
                List<String> lines = readEncryptedLines(PAYROLL_FILE);
                for (String line : lines) displayArea.append(line + "\n");
                log("Viewed payroll records"); // R004
            } catch (Exception ex) {
                showError("View failed", ex);  // R007
            }
        });

        // R005, R009, R001: Admin-only deletion with confirmation and backup
        deleteButton.addActionListener(e -> {
            if (!currentUser.equals("admin")) {
                showMessage("Only admin can delete payroll"); // R001, R005
                return;
            }
            int confirm = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete the payroll file?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                try {
                    backupFile(); // R009
                    Files.deleteIfExists(Paths.get(PAYROLL_FILE));
                    displayArea.setText("Payroll file deleted.\n");
                    log("Payroll file deleted by admin"); // R004
                } catch (IOException ex) {
                    showError("Deletion failed", ex);     // R007
                }
            }
        });
    }

    // R002, R0010: Validate login using SHA-256 hashed credentials from config
    private boolean validateLogin(String username, String password) throws Exception {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(CONFIG_FILE)) {
            props.load(fis);
        }
        String storedHash = props.getProperty(username);
        return storedHash != null && storedHash.equals(hash(password));
    }

    // R002: SHA-256 hashing for password security
    private String hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashed = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashed) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // R003: Escape potentially dangerous CSV inputs
    private String escapeCSV(String input) {
        return input.replaceAll("^[=+@-]", "'");
    }

    // R008: Write encrypted payroll record using AES
    private void writeEncryptedLine(String file, String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        try (FileOutputStream fos = new FileOutputStream(file, true)) {
            fos.write(Base64.getEncoder().encode(encrypted));
            fos.write("\n".getBytes());
        }
    }

    // R008: Decrypt and display payroll records
    private List<String> readEncryptedLines(String file) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                byte[] decoded = Base64.getDecoder().decode(line);
                String decrypted = new String(cipher.doFinal(decoded));
                lines.add(decrypted);
            }
        }
        return lines;
    }

    // R009: Create a timestamped backup of the payroll file
    private void backupFile() throws IOException {
        File dir = new File(BACKUP_DIR);
        if (!dir.exists()) dir.mkdirs();
        String backupName = BACKUP_DIR + "payroll_backup_" + System.currentTimeMillis() + ".csv";
        Files.copy(Paths.get(PAYROLL_FILE), Paths.get(backupName), StandardCopyOption.REPLACE_EXISTING);
    }

    private void showMessage(String msg) {
        JOptionPane.showMessageDialog(this, msg);
    }

    // R007: Show only basic message to user, log technical details to file
    private void showError(String msg, Exception ex) {
        showMessage(msg);
        try (FileWriter fw = new FileWriter("error.log", true)) {
            fw.write(new Date() + " - " + msg + ": " + ex.toString() + "\n");
        } catch (IOException ignored) {}
    }

    // R004: Log user actions for traceability
    private void log(String msg) {
        logger.info(currentUser + ": " + msg);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new TrustPaySecure().setVisible(true));
    }
}

