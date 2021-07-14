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

    void addBurpMessage(SharedRequest shareable) {
        sharedRequests.add(shareable);
        fireTableDataChanged();
    }

    void removeBurpMessage(int rowIndex) {
        sharedRequests.remove(rowIndex);
        fireTableDataChanged();
    }

    void clearTable() {
        sharedRequests.clear();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return sharedRequests.size();
    }

    @Override
    public String getColumnName(int col) {
        if (col == 0) {
            return "Link To Share";
        } else {
            return "Shared Request Url";
        }
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public String getValueAt(int row, int col) {
        if (col == 0) {
            return sharedRequests.get(row).getShareableUrl();
        } else {
            return sharedRequests.get(row).getDescription();
        }
    }

    SharedRequest getShareableAtIndex(int rowIndex) {
        return sharedRequests.get(rowIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }
}
