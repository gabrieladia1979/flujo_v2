import io

from scripts.audit_local_datasets import audit_stream


def test_audit_reports_conflicting_labels_and_partition_leakage_without_content():
    stream = io.StringIO("subject,body,Label,particion,group_id\n"
                        "Notice,Same body,0,train,a\n"
                        "NOTICE,Same   body,1,test,a\n"
                        "Different,Same body,0,validation,b\n")
    report, keys = audit_stream(stream, "fixture")
    assert report["rows"] == 3
    assert report["duplicate_message_rows"] == 1
    assert report["conflicting_message_groups"] == 1
    assert report["conflicting_body_groups"] == 1
    assert report["message_groups_across_partitions"] == 1
    assert report["body_groups_across_partitions"] == 1
    assert report["declared_groups_across_partitions"] == 1
    assert len(keys) == 2
    assert "Same body" not in str(report)
