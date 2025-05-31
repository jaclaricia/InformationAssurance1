import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.*;

public class TrustPaySecure extends JFrame {
    private static final String CONFIG_FILE = "config.txt";
    private static final String LOG_FILE = "audit.log";
    private static final String PAYROLL_FILE = "payroll.csv";
    private static final String BACKUP_DIR = "backups/";
    private static final String ERROR_LOG = "error.log";
    private static final String ENCRYPTION_KEY = "1234567890abcdef";

    private JTextField nameField, salaryField, userField;
    private JTextArea displayArea;
    private JPasswordField passField;
    private JButton addButton, deleteButton, viewButton, loginButton, logoutButton, clearButton;
    private JPanel loginPanel, payrollPanel;
    private JLabel userLabel;

    private boolean isLoggedIn = false;
    private String currentUser = null;
    private Logger logger;

    public TrustPaySecure() {
        initializeLogger();
        initializeFiles();
        setupUI();
        setupEventListeners();
    }

    private void initializeLogger() {
        logger = Logger.getLogger("AuditLog");
        try {
            FileHandler handler = new FileHandler(LOG_FILE, true);
            logger.addHandler(handler);
            logger.setUseParentHandlers(false);
            handler.setFormatter(new SimpleFormatter());
        } catch (IOException e) {
            System.err.println("Failed to initialize logger: " + e.getMessage());
        }
    }

    private void initializeFiles() {
        try {
            Files.createDirectories(Paths.get(BACKUP_DIR));

            // Force regenerate config file for testing login
            Files.deleteIfExists(Paths.get(CONFIG_FILE));
            createDefaultConfig();

            if (!Files.exists(Paths.get(PAYROLL_FILE))) {
                Files.createFile(Paths.get(PAYROLL_FILE));
            }
        } catch (Exception e) {
            showError("Initialization failed", e);
        }
    }

    private void createDefaultConfig() throws Exception {
        Properties props = new Properties();
        props.setProperty("admin", hash("admin123"));
        props.setProperty("user", hash("user123"));

        try (FileOutputStream fos = new FileOutputStream(CONFIG_FILE)) {
            props.store(fos, "Default user credentials - Change these passwords!");
        }
    }

    private void setupUI() {
        setTitle("TrustPay - Secure Payroll System");
        setSize(700, 500);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setupLoginPanel();
        setupPayrollPanel();
        setContentPane(loginPanel);
    }

    private void setupLoginPanel() {
        loginPanel = new JPanel(new GridBagLayout());
        loginPanel.setBorder(BorderFactory.createTitledBorder("Login to TrustPay"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);

        userField = new JTextField(15);
        passField = new JPasswordField(15);
        loginButton = new JButton("Login");

        gbc.gridx = 0; gbc.gridy = 0;
        loginPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1;
        loginPanel.add(userField, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        loginPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        loginPanel.add(passField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        loginPanel.add(loginButton, gbc);

        gbc.gridy = 3;
        JLabel infoLabel = new JLabel("<html><center>Default login:<br/>admin/admin123 or user/user123</center></html>");
        infoLabel.setForeground(Color.GRAY);
        loginPanel.add(infoLabel, gbc);
    }

    private void setupPayrollPanel() {
        payrollPanel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new BorderLayout());
        userLabel = new JLabel();
        logoutButton = new JButton("Logout");
        topPanel.add(userLabel, BorderLayout.WEST);
        topPanel.add(logoutButton, BorderLayout.EAST);
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel inputPanel = new JPanel(new GridLayout(3, 2, 10, 10));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Payroll Entry"));
        nameField = new JTextField();
        salaryField = new JTextField();
        inputPanel.add(new JLabel("Employee Name:"));
        inputPanel.add(nameField);
        inputPanel.add(new JLabel("Salary:"));
        inputPanel.add(salaryField);

        JPanel buttonPanel = new JPanel(new FlowLayout());
        addButton = new JButton("Add Entry");
        deleteButton = new JButton("Delete Payroll File");
        viewButton = new JButton("View Payroll Records");
        clearButton = new JButton("Clear Display");
        buttonPanel.add(addButton);
        buttonPanel.add(viewButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(deleteButton);

        displayArea = new JTextArea(15, 50);
        displayArea.setEditable(false);
        displayArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(displayArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Payroll Records"));

        payrollPanel.add(topPanel, BorderLayout.NORTH);
        payrollPanel.add(inputPanel, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(scrollPane, BorderLayout.CENTER);
        payrollPanel.add(bottomPanel, BorderLayout.SOUTH);
    }

    private void setupEventListeners() {
        loginButton.addActionListener(e -> performLogin());
        userField.addActionListener(e -> performLogin());
        passField.addActionListener(e -> performLogin());
        logoutButton.addActionListener(e -> logout());
        addButton.addActionListener(e -> addPayrollEntry());
        viewButton.addActionListener(e -> viewPayrollRecords());
        clearButton.addActionListener(e -> displayArea.setText(""));
        deleteButton.addActionListener(e -> deletePayrollFile());
    }

    private void performLogin() {
        try {
            String user = userField.getText().trim();
            String pass = new String(passField.getPassword());

            if (user.isEmpty() || pass.isEmpty()) {
                showMessage("Please enter both username and password");
                return;
            }

            if (validateLogin(user, pass)) {
                isLoggedIn = true;
                currentUser = user;
                log("User logged in: " + user);
                userLabel.setText("Logged in as: " + user + " | Role: " + (user.equals("admin") ? "Administrator" : "User"));
                deleteButton.setVisible(user.equals("admin"));
                setContentPane(payrollPanel);
                revalidate();
                repaint();
                passField.setText("");
            } else {
                showMessage("Invalid username or password");
                log("Failed login attempt: " + user);
                passField.setText("");
            }
        } catch (Exception ex) {
            showError("Login failed", ex);
        }
    }

    private void logout() {
        isLoggedIn = false;
        log("User logged out: " + currentUser);
        currentUser = null;
        displayArea.setText("");
        nameField.setText("");
        salaryField.setText("");
        userField.setText("");
        passField.setText("");
        setContentPane(loginPanel);
        revalidate();
        repaint();
    }

    private void addPayrollEntry() {
        if (!isLoggedIn) {
            showMessage("Please log in first");
            return;
        }

        try {
            String name = nameField.getText().trim();
            String salary = salaryField.getText().trim();

            if (name.isEmpty() || salary.isEmpty()) {
                showMessage("Please fill in all fields");
                return;
            }

            if (!name.matches("[A-Za-z\\s]+")) {
                showMessage("Name can only contain letters and spaces");
                return;
            }

            if (!salary.matches("\\d+(\\.\\d{1,2})?")) {
                showMessage("Salary must be a valid number (e.g., 50000 or 50000.50)");
                return;
            }

            String record = escapeCSV(name) + "," + escapeCSV(salary);
            backupFile();
            writeEncryptedLine(PAYROLL_FILE, record);
            displayArea.append("✓ Added: " + name + " - $" + salary + "\n");
            log("Record added: " + record);
            nameField.setText("");
            salaryField.setText("");
            showMessage("Employee record added successfully!");
        } catch (Exception ex) {
            showError("Failed to add entry", ex);
        }
    }

    private void viewPayrollRecords() {
        if (!isLoggedIn) {
            showMessage("Please log in first");
            return;
        }

        try {
            displayArea.setText("Loading payroll records...\n");
            displayArea.append("==========================================\n");

            List<String> lines = readEncryptedLines(PAYROLL_FILE);

            if (lines.isEmpty()) {
                displayArea.append("No payroll records found.\n");
            } else {
                displayArea.append(String.format("%-25s %s\n", "Employee Name", "Salary"));
                displayArea.append("------------------------------------------\n");

                for (String line : lines) {
                    if (!line.trim().isEmpty()) {
                        String[] parts = line.split(",");
                        if (parts.length >= 2) {
                            displayArea.append(String.format("%-25s $%s\n", parts[0].trim(), parts[1].trim()));
                        }
                    }
                }
                displayArea.append("==========================================\n");
                displayArea.append("Total records: " + lines.size() + "\n");
            }

            log("Viewed payroll records");

        } catch (Exception ex) {
            displayArea.append("Error loading records: " + ex.getMessage() + "\n");
            showError("Failed to view records", ex);
        }
    }

    private void deletePayrollFile() {
        if (!currentUser.equals("admin")) {
            showMessage("Only administrators can delete the payroll file");
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to delete ALL payroll records?\n\nThis action cannot be undone!",
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (confirm == JOptionPane.YES_OPTION) {
            try {
                backupFile();
                Files.deleteIfExists(Paths.get(PAYROLL_FILE));
                Files.createFile(Paths.get(PAYROLL_FILE));
                displayArea.setText("Payroll file deleted successfully.\nA backup has been created.\n");
                log("Payroll file deleted by admin");
                showMessage("Payroll file deleted. Backup created in " + BACKUP_DIR);
            } catch (Exception ex) {
                showError("Failed to delete payroll file", ex);
            }
        }
    }

    private boolean validateLogin(String username, String password) throws Exception {
        if (!Files.exists(Paths.get(CONFIG_FILE))) {
            createDefaultConfig();
        }

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(CONFIG_FILE)) {
            props.load(fis);
        }

        String storedHash = props.getProperty(username);
        return storedHash != null && storedHash.equals(hash(password));
    }

    private String hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashed = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashed) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String escapeCSV(String input) {
        return input.replaceAll("^[=+@-]", "'").replaceAll("[\"']", "");
    }

    private void writeEncryptedLine(String filename, String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
        String encodedData = Base64.getEncoder().encodeToString(encrypted);

        try (FileWriter writer = new FileWriter(filename, true)) {
            writer.write(encodedData + System.lineSeparator());
        }
    }

    private List<String> readEncryptedLines(String filename) throws Exception {
        List<String> decryptedLines = new ArrayList<>();

        if (!Files.exists(Paths.get(filename))) {
            return decryptedLines;
        }

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    try {
                        byte[] decoded = Base64.getDecoder().decode(line.trim());
                        String decrypted = new String(cipher.doFinal(decoded), "UTF-8");
                        decryptedLines.add(decrypted);
                    } catch (Exception e) {
                        System.err.println("Skipping corrupted line: " + e.getMessage());
                    }
                }
            }
        }

        return decryptedLines;
    }

    private void backupFile() throws IOException {
        if (!Files.exists(Paths.get(PAYROLL_FILE))) {
            return;
        }

        String timestamp = String.valueOf(System.currentTimeMillis());
        String backupName = BACKUP_DIR + "payroll_backup_" + timestamp + ".csv";
        Files.copy(Paths.get(PAYROLL_FILE), Paths.get(backupName), StandardCopyOption.REPLACE_EXISTING);
    }

    private void showMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "TrustPay", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showError(String message, Exception ex) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
        try (FileWriter fw = new FileWriter(ERROR_LOG, true)) {
            fw.write(new Date() + " - " + message + ": " + ex.toString() + "\n");
            ex.printStackTrace(new PrintWriter(fw));
            fw.write("\n");
        } catch (IOException ignored) {
            System.err.println("Failed to log error: " + ignored.getMessage());
        }
    }

    private void log(String message) {
        if (logger != null) {
            logger.info((currentUser != null ? currentUser : "SYSTEM") + ": " + message);
        }
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            System.out.println("Using default look and feel");
        }

        SwingUtilities.invokeLater(() -> {
            new TrustPaySecure().setVisible(true);
        });
    }
}
