package sharerequests;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

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

    private void createLinkForSelectedRequests(IContextMenuInvocation invocation) {
        HttpRequestResponse httpRequestResponse =
                new HttpRequestResponse();
        for (IHttpRequestResponse message : invocation.getSelectedMessages()) {
            new SwingWorker<Boolean, Void>() {
                @Override
                public Boolean doInBackground() {
                    httpRequestResponse.setRequest(message.getRequest());
                    httpRequestResponse.setHttpService(message.getHttpService());
                    sharedValues.getSharedLinksModel().addBurpMessage(httpRequestResponse);
                    JOptionPane.showMessageDialog(null, "Link has been generated! Goto the Burp Shared Requests tab to share it.");
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
                Objects.equals(IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.getInvocationContext())) {
            menues.addAll(createLinkMenu(invocation));
        }
        return menues;
    }
}
