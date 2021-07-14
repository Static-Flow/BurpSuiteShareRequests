package sharerequests;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * The GUI for the extension. If the user has elected to be remembered we
 * skip the login page. Otherwise the UI starts out at the signup page.
 */
public class GuiPanel extends JPanel {

    private final SharedValues sharedValues;
    private JTextField usernameField;
    private JTextField emailField;
    private JTextField passwordField;
    private JPanel VerifyPanel;
    private JTextField codeField;
    private JPanel signUpPanel;
    private JPanel InfoPanel;
    private JPanel ProfilePanel;
    private JTable LinksTable;
    private JPanel loginPanel;
    private JTextField loginUsername;
    private JTextField loginPassword;

    public GuiPanel(SharedValues sv) {
        this.sharedValues = sv;
        this.initComponents();
        if(sharedValues.hasLoggedInBefore()) {
            signUpPanel.setVisible(false);
            loginPanel.setVisible(true);
        }
        if( this.sharedValues.getCallbacks().loadExtensionSetting("refresh") != null ) {
            sharedValues.getCallbacks().printOutput("User is remembered");
            loginPanel.setVisible(false);
            ProfilePanel.setVisible(true);
        }
    }

    /**
     * Generates the UI.
     */
    private void initComponents() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridBagLayout());
        signUpPanel = new JPanel();
        signUpPanel.setLayout(new GridBagLayout());
        signUpPanel.setEnabled(true);
        signUpPanel.setVisible(true);
        GridBagConstraints gbc;
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(signUpPanel, gbc);
        final JLabel label1 = new JLabel();
        label1.setText("Password");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        signUpPanel.add(label1, gbc);
        passwordField = new JPasswordField();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        signUpPanel.add(passwordField, gbc);
        final JLabel label2 = new JLabel();
        label2.setText("Email");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        signUpPanel.add(label2, gbc);
        emailField = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        signUpPanel.add(emailField, gbc);
        JButton signUpButton = new JButton();
        signUpButton.setText("Sign Up");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        signUpPanel.add(signUpButton, gbc);
        JLabel hasAccountLink = new JLabel("Click here if you have an account");
        hasAccountLink.setForeground(Color.BLUE.darker());
        hasAccountLink.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        signUpPanel.add(hasAccountLink, gbc);
        final JLabel label3 = new JLabel();
        label3.setText("Username");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        signUpPanel.add(label3, gbc);
        usernameField = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        signUpPanel.add(usernameField, gbc);
        InfoPanel = new JPanel();
        InfoPanel.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(InfoPanel, gbc);
        final JLabel label4 = new JLabel();
        label4.setText("<html>This extension allows you to create shareable " +
                "links to Burp Suite requests. <br>When someone visit the " +
                "generated links, in a browser proxied by Burp Suite with " +
                "this extension installed, <br>the request as you shared it " +
                "will be imported into their repeater tab. <br> Links can be generated from right click context menus on requests in the following places: <br> <ul><li>Repeater Tab</li><li>HTTP History Tab</li><li>Intercept Tab</li><li>Site Map Table and Tree</li></ul>" +
                "Note: If you want to view someone's shareable " +
                "link you do not need an account. Accounts are only " +
                "needed for creating shared requests.</html>");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        InfoPanel.add(label4, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        InfoPanel.add(new JSeparator(SwingConstants.HORIZONTAL), gbc);
        VerifyPanel = new JPanel();
        VerifyPanel.setLayout(new GridBagLayout());
        VerifyPanel.setEnabled(false);
        VerifyPanel.setVisible(false);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(VerifyPanel, gbc);
        codeField = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        VerifyPanel.add(codeField, gbc);
        final JLabel label5 = new JLabel();
        label5.setText("Verification Code");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        VerifyPanel.add(label5, gbc);
        JButton verifyButton = new JButton();
        verifyButton.setText("Verify");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        VerifyPanel.add(verifyButton, gbc);
        ProfilePanel = new JPanel();
        ProfilePanel.setVisible(false);
        ProfilePanel.setLayout(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(ProfilePanel, gbc);
        LinksTable = new JTable();
        JScrollPane sp = new JScrollPane(LinksTable);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        ProfilePanel.add(sp, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        JButton logoutButton = new JButton("Logout");
        ProfilePanel.add(logoutButton, gbc);
        loginPanel = new JPanel();
        loginPanel.setLayout(new GridBagLayout());
        loginPanel.setVisible(false);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(loginPanel, gbc);
        final JLabel label6 = new JLabel();
        label6.setText("Username");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        loginPanel.add(label6, gbc);
        loginUsername = new JTextField();
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(loginUsername, gbc);
        final JLabel label7 = new JLabel();
        label7.setText("Password");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        loginPanel.add(label7, gbc);
        loginPassword = new JPasswordField();
        loginPassword.setText("");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(loginPassword, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JCheckBox rememberMe = new JCheckBox("Remember Me");
        loginPanel.add(rememberMe, gbc);
        JButton loginButton = new JButton();
        loginButton.setText("Login");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(loginButton, gbc);
        JButton forgetMeButton = new JButton();
        forgetMeButton.setText("Forget Me");
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        loginPanel.add(forgetMeButton, gbc);
        add(mainPanel);

        setupProfileTable();

        wireUpLogoutButton(logoutButton);

        wireUpSkipSignupLink(hasAccountLink);

        wireUpForgetMeButton(forgetMeButton);

        wireUpLoginButton(rememberMe, loginButton);

        wireUpSignUpButton(signUpButton);

        wireUpVerifyCodeButton(verifyButton);
    }


    private void wireUpVerifyCodeButton(JButton verifyButton) {
        verifyButton.addActionListener(e -> {
            if (sharedValues.getCognitoClient().verifyCode(sharedValues.getCognitoClient().getUsername(), codeField.getText())) {
                VerifyPanel.setVisible(false);
                loginPanel.setVisible(true);

            } else {
                sharedValues.getCallbacks().printError("bad code");
            }
        });
    }

    private void wireUpSignUpButton(JButton signUpButton) {
        signUpButton.addActionListener(e -> {
            if (sharedValues.getCognitoClient().signup(usernameField.getText(), passwordField.getText(), emailField.getText())) {
                sharedValues.getCognitoClient().setUsername(usernameField.getText());
                signUpPanel.setVisible(false);
                VerifyPanel.setVisible(true);
            } else {
                sharedValues.getCallbacks().printError("Bad signup");
            }
        });
    }

    private void wireUpLoginButton(JCheckBox rememberMe, JButton loginButton) {
        loginButton.addActionListener(e -> {
            if(sharedValues.getCognitoClient().login(loginUsername.getText()
                    ,loginPassword.getText(), rememberMe.isSelected())) {
                try {
                    sharedValues.initUser(loginUsername.getText());
                    loginPanel.setVisible(false);
                    ProfilePanel.setVisible(true);
                } catch (Exception exception) {
                    sharedValues.getCallbacks().printError(exception.getMessage());
                }
            } else {
                sharedValues.getCallbacks().printError("Bad login");
            }
        });
    }

    private void wireUpForgetMeButton(JButton forgetMeButton) {
        forgetMeButton.addActionListener(e -> {
            int input = JOptionPane.showConfirmDialog(null, "Forget this " +
                    "account?");
            if (input == 0) {
                sharedValues.clearHasLoggedInBefore();
                loginPanel.setVisible(false);
                signUpPanel.setVisible(true);
            }
        });
    }

    private void wireUpSkipSignupLink(JLabel hasAccountLink) {
        hasAccountLink.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                signUpPanel.setVisible(false);
                loginPanel.setVisible(true);
            }
        });
    }

    private void wireUpLogoutButton(JButton logoutButton) {
        logoutButton.addActionListener(e -> {
            sharedValues.getCognitoClient().logout();
            ProfilePanel.setVisible(false);
            loginPanel.setVisible(true);
        });
    }

    private void setupProfileTable() {
        LinksTable.setModel(this.sharedValues.getSharedLinksModel());

        final JPopupMenu popupMenu = new JPopupMenu();
        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int rowAtPoint = LinksTable.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), LinksTable));
                    if (rowAtPoint > -1) {
                        LinksTable.setRowSelectionInterval(rowAtPoint, rowAtPoint);
                    }
                });
            }
            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                //this just isn't needed but I have to override it
            }
            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                //this just isn't needed but I have to override it
            }
        });
        JMenuItem removeLinkItem = new JMenuItem("Remove Link");
        removeLinkItem.addActionListener(e -> {
            try {
                SharedLinksModel model = ((SharedLinksModel) LinksTable.getModel());
                SharedRequest shareable =
                        model.getShareableAtIndex(LinksTable.getSelectedRow());
                if (sharedValues.getCognitoClient().deleteMessage(shareable.getShareableAWSUrl())) {
                    ((SharedLinksModel) LinksTable.getModel()).removeBurpMessage(LinksTable.getSelectedRow());
                } else {
                    sharedValues.getCallbacks().printError("Could not delete " +
                            "shared request");
                }
            } catch (Exception ex) {
                sharedValues.getCallbacks().printError(ex.getMessage());
            }
        });
        JMenuItem getLinkItem = new JMenuItem("Get Link");
        getLinkItem.addActionListener(e -> {
            String shareableUrl =
                    ((SharedLinksModel) LinksTable.getModel()).getShareableAtIndex(LinksTable.getSelectedRow()).getShareableUrl();
            try {
                StringSelection stringSelection =
                        new StringSelection(shareableUrl);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(stringSelection, null);
                JOptionPane.showMessageDialog(null, "Link has been added to the clipboard");
            } catch (Exception ex) {
                sharedValues.getCallbacks().printError(ex.getMessage());
            }

        });
        popupMenu.add(getLinkItem);
        popupMenu.add(removeLinkItem);
        LinksTable.setComponentPopupMenu(popupMenu);
    }

}
