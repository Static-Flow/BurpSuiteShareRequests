package sharerequests;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Handles the context menus used to send requests to the Share extension.
 * Currently a user can send a request to be shared in the following spots:
 * +Repeater Tab
 * +HTTP History Tab
 * +Intercept Tab
 * +Site Map Table and Tree
 */
public class ManualRequestSenderContextMenu implements IContextMenuFactory {

    private final SharedValues sharedValues;

    public ManualRequestSenderContextMenu(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }


    private Collection<? extends JMenuItem> createLinkMenu(IContextMenuInvocation invocation) {
        JMenuItem click = new JMenuItem("create link");
        click.addActionListener(e ->
                createLinkForSelectedRequests(invocation));
        ArrayList<JMenuItem> menuList = new ArrayList<>();
        menuList.add(click);
        return menuList;
    }

    /**
     * When a user clicks the "create link" button the selected request is
     * converted into an encrypted and shareable format and sent via the API
     * to be stored. The API returns a shareable link that users can give to
     * others.
     * @param invocation The Burp Request to generate a shareable link to
     */
    private void createLinkForSelectedRequests(IContextMenuInvocation invocation) {
        HttpRequestResponse httpRequestResponse =
                new HttpRequestResponse();
        for (IHttpRequestResponse message : invocation.getSelectedMessages()) {
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    httpRequestResponse.setRequest(message.getRequest());
                    httpRequestResponse.setHttpService(message.getHttpService());
                    try {
                        SharedRequest shareable =
                                sharedValues.getCognitoClient().sendMessage(httpRequestResponse);
                        sharedValues.getSharedLinksModel().addBurpMessage(shareable);
                        JOptionPane.showMessageDialog(null, "Link has been generated! Goto the Burp Shared Requests tab to share it.");
                    } catch (Exception e) {
                        sharedValues.getCallbacks().printError(e.getMessage());
                    }
                    return Boolean.TRUE;
                }

                @Override
                public void done() {
                    //we don't need to do any cleanup so this is empty
                }
            }.execute();
        }

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menues = new ArrayList<>();
        if (Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.getInvocationContext()) ||
                Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.getInvocationContext()) ||
                Objects.equals(IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE, invocation.getInvocationContext()) ||
                Objects.equals(IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE, invocation.getInvocationContext())) {
            menues.addAll(createLinkMenu(invocation));
        }
        return menues;
    }
}
