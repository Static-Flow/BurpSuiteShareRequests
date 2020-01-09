package sharerequests;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.Base64;

public class ExtensionPanel
        extends JPanel {
    private static final long serialVersionUID = 1L;
    private SharedValues sharedValues;

    public ExtensionPanel(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
        this.initComponents();
    }

    private void initComponents() {
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWeights = new double[]{1.0, 1.0};
        gridBagLayout.rowWeights = new double[]{0.0, 1.0};
        setLayout(gridBagLayout);

        //info panel
        JPanel infoPanel = new JPanel(new BorderLayout());
        JLabel explainer = new JLabel();
        explainer.setHorizontalAlignment(SwingConstants.LEFT);
        infoPanel.add(explainer, BorderLayout.WEST);
        explainer.setText("<html>This extension allows you to create shareable links to Burp Suite requests. <br>" +
                "When others visit the generated links, in a browser proxied by Burp Suite with this extension installed, <br>" +
                "the request as you shared it will be imported into their repeater tab. <br> Links can be generated from" +
                " right click context menus on requests in the following places: <br> <ul><li>Repeater Tab</li>" +
                "<li>HTTP History Tab</li><li>Intercept Tab</li><li>Site Map Table and Tree</li></ul></html>\n");
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.insets = new Insets(5, 5, 5, 5);
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        add(infoPanel, gridBagConstraints);
        JPanel filler = new JPanel();
        gridBagConstraints.gridx = 1;
        add(filler, gridBagConstraints);
        //end info panel

        //shareable links
        JTable j = new JTable(this.sharedValues.getSharedLinksModel()) {
            public boolean getScrollableTracksViewportWidth() {
                return getPreferredSize().width < getParent().getWidth();
            }
        };
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        j.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        final JPopupMenu popupMenu = new JPopupMenu();
        popupMenu.addPopupMenuListener(new PopupMenuListener() {

            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int rowAtPoint = j.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), j));
                    if (rowAtPoint > -1) {
                        j.setRowSelectionInterval(rowAtPoint, rowAtPoint);

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
        removeLinkItem.addActionListener(e -> ((SharedLinksModel) j.getModel()).removeBurpMessage(j.getSelectedRow()));
        JMenuItem getHTMLLinkItem = new JMenuItem("Get HTML Link");
        getHTMLLinkItem.addActionListener(e -> {
            HttpRequestResponse burpMessage = ((SharedLinksModel) j.getModel()).getBurpMessageAtIndex(j.getSelectedRow());
            StringSelection stringSelection = new StringSelection(generateHTMLLink(burpMessage));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(null, "Link has been added to the clipboard");
        });
        JMenuItem getLinkItem = new JMenuItem("Get Link");
        getLinkItem.addActionListener(e -> {
            HttpRequestResponse burpMessage = ((SharedLinksModel) j.getModel()).getBurpMessageAtIndex(j.getSelectedRow());
            StringSelection stringSelection = new StringSelection("http://burpsharedrequest/" +
                    Base64.getEncoder().encodeToString(this.sharedValues.getGson().toJson(burpMessage).getBytes()));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(null, "Link has been added to the clipboard");
        });
        popupMenu.add(getLinkItem);
        popupMenu.add(getHTMLLinkItem);
        popupMenu.add(removeLinkItem);
        j.setComponentPopupMenu(popupMenu);
        JScrollPane sp = new JScrollPane(j);
        JPanel pane = new JPanel(new BorderLayout());
        pane.add(sp, BorderLayout.CENTER);
        GridBagConstraints optionsPanelConstraints = new GridBagConstraints();
        optionsPanelConstraints.fill = GridBagConstraints.BOTH;
        optionsPanelConstraints.weighty = 1;
        optionsPanelConstraints.weightx = 1;
        optionsPanelConstraints.gridwidth = 2;
        optionsPanelConstraints.gridx = 0;
        optionsPanelConstraints.gridy = 1;
        add(pane, optionsPanelConstraints);
        //end shareable links

    }

    private String generateHTMLLink(HttpRequestResponse burpMessage) {
        return "<a href='http://burpsharedrequest/" +
                Base64.getEncoder().encodeToString(this.sharedValues.getGson().toJson(burpMessage).getBytes())
                + "'>http://burpsharedrequest/</a>";
    }
}
