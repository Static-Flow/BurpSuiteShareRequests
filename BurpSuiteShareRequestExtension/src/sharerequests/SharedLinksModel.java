package sharerequests;

import burp.IBurpExtenderCallbacks;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

class SharedLinksModel extends AbstractTableModel {

    private final ArrayList<HttpRequestResponse> httpRequestResponses;
    private final IBurpExtenderCallbacks callbacks;

    SharedLinksModel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        httpRequestResponses = new ArrayList<>();
    }

    void addBurpMessage(HttpRequestResponse burpMessage) {
        httpRequestResponses.add(burpMessage);
        fireTableDataChanged();
    }

    void removeBurpMessage(int rowIndex) {
        httpRequestResponses.remove(rowIndex);
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return httpRequestResponses.size();
    }

    @Override
    public String getColumnName(int col) {
        return "URL";
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public String getValueAt(int rowIndex, int columnIndex) {
        return this.callbacks.getHelpers().analyzeRequest(
                httpRequestResponses.get(rowIndex)).getUrl().toString();
    }

    HttpRequestResponse getBurpMessageAtIndex(int rowIndex) {
        return httpRequestResponses.get(rowIndex);
    }

}
