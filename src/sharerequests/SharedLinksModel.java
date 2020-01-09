package sharerequests;

import burp.IBurpExtenderCallbacks;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

class SharedLinksModel extends AbstractTableModel {

    private final ArrayList<SharedRequest> sharedRequests;
    private final IBurpExtenderCallbacks callbacks;

    SharedLinksModel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        sharedRequests = new ArrayList<>();
    }

    void addBurpMessage(HttpRequestResponse burpMessage, String datetime) {
        sharedRequests.add(new SharedRequest(burpMessage, datetime));
        fireTableDataChanged();
    }

    void removeBurpMessage(int rowIndex) {
        sharedRequests.remove(rowIndex);
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return sharedRequests.size();
    }

    @Override
    public String getColumnName(int col) {
        if (col == 0) {
            return "URL";
        } else {
            return "Date Created";
        }
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public Object getValueAt(int row, int col) {
        Object temp = null;
        if (col == 0) {
            temp = this.callbacks.getHelpers().analyzeRequest(sharedRequests.get(row).getRequestResponse()).getUrl().toString();
        } else if (col == 1) {
            temp = sharedRequests.get(row).getDatetime();
        }
        return temp;
    }

    HttpRequestResponse getBurpMessageAtIndex(int rowIndex) {
        return sharedRequests.get(rowIndex).getRequestResponse();
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }
}
