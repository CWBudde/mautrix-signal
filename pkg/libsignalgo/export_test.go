package libsignalgo

// NewDeviceTransferKeyForTest wraps existing key material; the API has no
// constructor for it. Both builds declare DeviceTransferKey{privateKey []byte}.
func NewDeviceTransferKeyForTest(privateKey []byte) *DeviceTransferKey {
	return &DeviceTransferKey{privateKey: privateKey}
}
