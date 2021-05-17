CREATE OR REPLACE PACKAGE BODY awlrs_alerts_api
AS
  -------------------------------------------------------------------------
  --   PVCS Identifiers :-
  --
  --       PVCS id          : $Header:   //new_vm_latest/archives/awlrs/admin/pck/awlrs_alerts_api.pkb-arc   1.11   Apr 01 2021 14:52:44   Barbara.Odriscoll  $
  --       Date into PVCS   : $Date:   Apr 01 2021 14:52:44  $
  --       Module Name      : $Workfile:   awlrs_alerts_api.pkb  $
  --       Date fetched Out : $Modtime:   Mar 26 2021 09:19:46  $
  --       Version          : $Revision:   1.11  $
  --
  -----------------------------------------------------------------------------------
  -- Copyright (c) 2020 Bentley Systems Incorporated.  All rights reserved.
  -----------------------------------------------------------------------------------
  --
  --g_body_sccsid is the SCCS ID for the package body
  g_body_sccsid   CONSTANT  VARCHAR2(2000) := '"$Revision:   1.11  $"';
  g_package_name  CONSTANT  VARCHAR2 (30)  := 'awlrs_alerts_api';
  --
  --Role constants--
  cv_hig_admin    CONSTANT VARCHAR2(9)   := 'HIG_ADMIN';
  cv_alert_admin  CONSTANT VARCHAR2(11)    := 'ALERT_ADMIN';
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION get_version
    RETURN VARCHAR2
    IS
  BEGIN
    RETURN g_sccsid;
  END get_version;

  --
  -----------------------------------------------------------------------------
  --
  FUNCTION get_test
    RETURN VARCHAR2
    IS
  BEGIN
    RETURN g_sccsid;
  END get_test;
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION get_body_version
    RETURN VARCHAR2
    IS
  BEGIN
    RETURN g_body_sccsid;
  END get_body_version;

  --
  -----------------------------------------------------------------------------
  --
  FUNCTION privs_check (pi_role_name  IN  varchar2) 
     RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM dba_role_privs
     WHERE granted_role = pi_role_name
       AND grantee      = SYS_CONTEXT('NM3_SECURITY_CTX','USERNAME');
     
    RETURN (lv_cnt > 0);  
    --
  END privs_check;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION privs_check RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM dba_role_privs
     WHERE granted_role IN (cv_hig_admin ,cv_alert_admin)
       AND grantee      = SYS_CONTEXT('NM3_SECURITY_CTX','USERNAME');
     
    RETURN (lv_cnt > 0);  
    --
  END privs_check;
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION get_screen_text(pi_ita_inv_type    IN  nm_inv_type_attribs.ita_inv_type%TYPE
                          ,pi_ita_attrib_name IN  nm_inv_type_attribs.ita_attrib_name%TYPE) RETURN nm_inv_type_attribs.ita_scrn_text%TYPE
  IS
  --
    lr_ita_rec  nm_inv_type_attribs%ROWTYPE;
    lv_retval   nm_inv_type_attribs.ita_scrn_text%TYPE;
  --  
  BEGIN
     --
     lr_ita_rec := nm3get.get_ita(pi_ita_inv_type      => pi_ita_inv_type
	                            ,pi_ita_attrib_name   => pi_ita_attrib_name);
     --
     lv_retval := lr_ita_rec.ita_scrn_text;
     --
     RETURN lv_retval;
     --
END get_screen_text; 
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_trg_alert_types(po_message_severity    OUT  hig_codes.hco_code%TYPE
                               ,po_message_cursor      OUT  sys_refcursor
                               ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT halt_alert_type         alert_type
          ,halt_id                 alert_id
          ,halt_nit_inv_type       inv_type
          ,nit_descr               alert_for
          ,halt_description        descr_
          ,halt_operation          operation
          ,halt_table_name         table_name
          ,halt_trigger_name       trigger_name
          ,CASE 
             WHEN halt_trigger_name IS NULL THEN 'Not Created'
             ELSE hig_alert.get_trigger_status(pi_trigger_name => halt_trigger_name)
           END                     trg_status   
          ,halt_immediate          immediate_
          ,halt_trigger_count      batch_email_threshold
          ,halt_frequency_id       batch_email_freq_id
          ,hsfr_meaning            batch_email_freq_descr
      FROM hig_alert_types
          ,nm_inv_types_all
          ,hig_scheduling_frequencies
     WHERE halt_alert_type   = 'T'     
       AND halt_nit_inv_type = nit_inv_type(+)
       AND halt_frequency_id = hsfr_frequency_id(+)
    ORDER BY halt_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_trg_alert_types;                                                          

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_trg_alert_type(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                              ,po_message_severity        OUT hig_codes.hco_code%TYPE
                              ,po_message_cursor          OUT sys_refcursor
                              ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT halt_alert_type         alert_type
          ,halt_id                 alert_id
          ,halt_nit_inv_type       inv_type
          ,nit_descr               alert_for
          ,halt_description        descr_
          ,halt_operation          operation
          ,halt_table_name         table_name
          ,halt_trigger_name       trigger_name
          ,CASE 
             WHEN halt_trigger_name IS NULL THEN 'Not Created'
             ELSE hig_alert.get_trigger_status(pi_trigger_name => halt_trigger_name)
           END                     trg_status   
          ,halt_immediate          immediate_
          ,halt_trigger_count      batch_email_threshold
          ,halt_frequency_id       batch_email_freq_id
          ,hsfr_meaning            batch_email_freq_descr
      FROM hig_alert_types
          ,nm_inv_types_all
          ,hig_scheduling_frequencies
     WHERE halt_alert_type   = 'T'          
       AND halt_id           = pi_alert_id     
       AND halt_nit_inv_type = nit_inv_type(+)
       AND halt_frequency_id = hsfr_frequency_id(+);
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_trg_alert_type;                           

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_trg_alert_types(pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                     ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                     ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                     ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                     ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                     ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                     ,pi_skip_n_rows          IN     PLS_INTEGER
                                     ,pi_pagesize             IN     PLS_INTEGER
                                     ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                     ,po_message_cursor          OUT sys_refcursor
                                     ,po_cursor                  OUT sys_refcursor)
  IS
      --
      lv_order_by         nm3type.max_varchar2;
      lv_filter           nm3type.max_varchar2;
      --
      lv_cursor_sql  nm3type.max_varchar2 :='SELECT halt_alert_type    alert_type'
                                                 ||',halt_id            alert_id'
                                                 ||',halt_nit_inv_type  inv_type'
                                                 ||',nit_descr          alert_for'
                                                 ||',halt_description   descr_'
                                                 ||',halt_operation     operation'
                                                 ||',halt_table_name    table_name'
                                                 ||',halt_trigger_name  trigger_name'
                                                 ||',CASE'
                                                   ||' WHEN halt_trigger_name IS NULL THEN ''Not Created'''
                                                   ||' ELSE hig_alert.get_trigger_status(pi_trigger_name => halt_trigger_name)'
                                                 ||' END                trg_status'
                                                 ||',halt_immediate     immediate_'
                                                 ||',halt_trigger_count batch_email_threshold'
                                                 ||',halt_frequency_id  batch_email_freq_id'
                                                 ||',hsfr_meaning       batch_email_freq_descr'
                                                 ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                            ||' FROM hig_alert_types'
                                                 ||',nm_inv_types_all'
                                                 ||',hig_scheduling_frequencies'
                                           ||' WHERE halt_alert_type   = ''T'''
                                             ||' AND halt_nit_inv_type = nit_inv_type(+)'
                                             ||' AND halt_frequency_id = hsfr_frequency_id(+)';
      --
      lt_column_data  awlrs_util.column_data_tab;
      --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_type'
                                ,pi_query_col    => 'halt_alert_type'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_for'
                                ,pi_query_col    => 'nit_descr'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'descr_'
                                ,pi_query_col    => 'halt_description'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'operation'
                                ,pi_query_col    => 'halt_operation'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'trg_status'
                                ,pi_query_col    => 'CASE'
                                                   ||' WHEN halt_trigger_name IS NULL THEN ''Not Created'''
                                                   ||' ELSE hig_alert.get_trigger_status(pi_trigger_name => halt_trigger_name)'
                                                 ||' END'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'immediate_'
                                ,pi_query_col    => 'halt_immediate'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'batch_email_threshold'
                                ,pi_query_col    => 'halt_trigger_count'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'batch_email_freq_descr'
                                ,pi_query_col    => 'hsfr_meaning'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'halt_id')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_trg_alert_types;  
   
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_sched_alert_types(po_message_severity        OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor          OUT sys_refcursor
                                 ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT halt_alert_type         alert_type
          ,halt_id                 alert_id
          ,halt_nit_inv_type       inv_type
          ,halt_hqt_id             query_id
          ,hqt_name                query_name   
          ,halt_description        descr_
          ,halt_frequency_id       frequency_id
          ,hsfr_meaning            freq_descr
          ,halt_last_run_date      last_run_date
          ,halt_next_run_date      next_run_date
          ,halt_suspend_query      suspend_query
      FROM hig_alert_types
          ,nm_inv_types_all
          ,hig_query_types
          ,hig_scheduling_frequencies
     WHERE halt_alert_type   = 'Q'
       AND halt_nit_inv_type = nit_inv_type(+)
       AND halt_hqt_id       = hqt_id(+) 
       AND halt_frequency_id = hsfr_frequency_id(+)
    ORDER BY halt_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_sched_alert_types;                                                                                         

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_sched_alert_type(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                                ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor          OUT sys_refcursor
                                ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT halt_alert_type         alert_type
          ,halt_id                 alert_id
          ,halt_nit_inv_type       inv_type
          ,halt_hqt_id             query_id
          ,hqt_name                query_name   
          ,halt_description        descr_
          ,halt_frequency_id       frequency_id
          ,hsfr_meaning            freq_descr
          ,halt_last_run_date      last_run_date
          ,halt_next_run_date      next_run_date
          ,halt_suspend_query      suspend_query
      FROM hig_alert_types
          ,nm_inv_types_all
          ,hig_query_types
          ,hig_scheduling_frequencies
     WHERE halt_alert_type   = 'Q'
       AND halt_id           = pi_alert_id
       AND halt_nit_inv_type = nit_inv_type(+)
       AND halt_hqt_id       = hqt_id(+) 
       AND halt_frequency_id = hsfr_frequency_id(+);       
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_sched_alert_type;                                                          

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_sched_alert_types(pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                       ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                       ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                       ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                       ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                       ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                       ,pi_skip_n_rows          IN     PLS_INTEGER
                                       ,pi_pagesize             IN     PLS_INTEGER
                                       ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                       ,po_message_cursor          OUT sys_refcursor
                                       ,po_cursor                  OUT sys_refcursor)
  IS
    --
    lv_order_by         nm3type.max_varchar2;
    lv_filter           nm3type.max_varchar2;
    --
    lv_cursor_sql  nm3type.max_varchar2 :='SELECT halt_alert_type    alert_type'
                                              ||',halt_id            alert_id'
                                              ||',halt_nit_inv_type  inv_type'
                                              ||',halt_hqt_id        query_id'
                                              ||',hqt_name           query_name'
                                              ||',halt_description   descr_'
                                              ||',halt_frequency_id  frequency_id'
                                              ||',hsfr_meaning       freq_descr'
                                              ||',halt_last_run_date last_run_date'
                                              ||',halt_next_run_date next_run_date'
                                              ||',halt_suspend_query suspend_query'
                                              ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                         ||' FROM hig_alert_types'
                                              ||',nm_inv_types_all'
                                              ||',hig_query_types'
                                              ||',hig_scheduling_frequencies'
                                        ||' WHERE halt_alert_type   = ''Q'''
                                          ||' AND halt_nit_inv_type = nit_inv_type(+)'
                                          ||' AND halt_hqt_id       = hqt_id(+)'
                                          ||' AND halt_frequency_id = hsfr_frequency_id(+)';
    --
    lt_column_data  awlrs_util.column_data_tab;
    --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_type'
                                ,pi_query_col    => 'halt_alert_type'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_id'
                                ,pi_query_col    => 'halt_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'inv_type'
                                ,pi_query_col    => 'halt_nit_inv_type'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'query_id'
                                ,pi_query_col    => 'halt_hqt_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'query_name'
                                ,pi_query_col    => 'hqt_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'descr_'
                                ,pi_query_col    => 'halt_description'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'frequency_id'
                                ,pi_query_col    => 'halt_frequency_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'freq_descr'
                                ,pi_query_col    => 'hsfr_meaning'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'last_run_date'
                                ,pi_query_col    => 'halt_last_run_date'
                                ,pi_datatype     => awlrs_util.c_datetime_col
                                ,pi_mask         => 'DD-MON-YYYY HH24:MI:SS'
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'next_run_date'
                                ,pi_query_col    => 'halt_next_run_date'
                                ,pi_datatype     => awlrs_util.c_datetime_col
                                ,pi_mask         => 'DD-MON-YYYY HH24:MI:SS'
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'suspend_query'
                                ,pi_query_col    => 'halt_suspend_query'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'halt_id')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_sched_alert_types;    
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_type_attribs(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                                  ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                                  ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor          OUT sys_refcursor
                                  ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hata_halt_id            alert_id
          ,hata_id                 attrib_id
          ,hata_attribute_name     attrib_name
          ,ita_scrn_text           attrib_name_descr
      FROM hig_alert_type_attributes
          ,nm_inv_type_attribs_all
     WHERE hata_halt_id        = pi_alert_id
       AND hata_attribute_name = ita_attrib_name
       AND ita_inv_type        = pi_inv_type
    ORDER BY ita_scrn_text;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_alert_type_attribs;                                  

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_type_attrib(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                                 ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                                 ,pi_attribute_name       IN     hig_alert_type_attributes.hata_attribute_name%TYPE 
                                 ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor          OUT sys_refcursor
                                 ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hata_halt_id            alert_id
          ,hata_id                 attrib_id
          ,hata_attribute_name     attrib_name
          ,ita_scrn_text           attrib_name_descr
      FROM hig_alert_type_attributes
          ,nm_inv_type_attribs_all
     WHERE hata_halt_id        = pi_alert_id
       AND hata_attribute_name = pi_attribute_name
       AND hata_attribute_name = ita_attrib_name
       AND ita_inv_type        = pi_inv_type
    ORDER BY ita_scrn_text;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_alert_type_attrib;                                                           

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_alert_type_attribs(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                                        ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                                        ,pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                        ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                        ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                        ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                        ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                        ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                        ,pi_skip_n_rows          IN     PLS_INTEGER
                                        ,pi_pagesize             IN     PLS_INTEGER
                                        ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                        ,po_message_cursor          OUT sys_refcursor
                                        ,po_cursor                  OUT sys_refcursor)
    IS
    --
    lv_order_by         nm3type.max_varchar2;
    lv_filter           nm3type.max_varchar2;
    --
    lv_cursor_sql  nm3type.max_varchar2 :='SELECT hata_halt_id        alert_id'
                                              ||',hata_id             attrib_id'
                                              ||',hata_attribute_name attrib_name'
                                              ||',ita_scrn_text       attrib_name_descr'
                                              ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                         ||' FROM hig_alert_type_attributes'
                                              ||',nm_inv_type_attribs_all'
                                        ||' WHERE hata_halt_id        = :pi_alert_id'
                                          ||' AND hata_attribute_name = ita_attrib_name'
                                          ||' AND ita_inv_type        = :pi_inv_type'
    ;
    --
    lt_column_data  awlrs_util.column_data_tab;
    --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_id'
                                ,pi_query_col    => 'hata_halt_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'attrib_id'
                                ,pi_query_col    => 'hata_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'attrib_name'
                                ,pi_query_col    => 'hata_attribute_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'attrib_name_descr'
                                ,pi_query_col    => 'ita_scrn_text'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'ita_scrn_text')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql
    USING pi_alert_id
         ,pi_inv_type
    ;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_alert_type_attribs; 
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION get_cond_attrib_meaning(pi_inv_type      IN   hig_alert_types.halt_nit_inv_type%TYPE
                                  ,pi_attrib_name   IN   hig_alert_type_conditions.hatc_attribute_name%TYPE
                                  ,pi_attrib_value  IN   hig_alert_type_conditions.hatc_attribute_value%TYPE
                                  ) RETURN varchar2
  IS
  --
  lv_value  varchar2(500);
  lv_retval varchar2(500);
  --	
  BEGIN
  --
  nm3inv.validate_flex_inv(p_inv_type      => pi_inv_type
		                  ,p_attrib_name   => pi_attrib_name
		                  ,pi_value        => pi_attrib_value
			              ,po_value        => lv_value
			              ,po_meaning      => lv_retval);
  --
  RETURN lv_retval;
  --   
  END get_cond_attrib_meaning;
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_type_conds(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                                ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                                ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor          OUT sys_refcursor
                                ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hatc_halt_id            alert_id
          ,hatc_id                 cond_id
          ,hatc_pre_bracket        cond_pre_bracket
          ,hatc_operator           cond_operator
          ,hatc_attribute_name     cond_attribute_name
          ,ita_scrn_text           attribute_name_text
          ,hatc_condition          cond_condition
          ,hatc_attribute_value    cond_attribute_value
          ,awlrs_alerts_api.get_cond_attrib_meaning(pi_inv_type,hatc_attribute_name,hatc_attribute_value) attrib_value_meaning
          ,hatc_post_bracket       cond_post_bracket
          ,hatc_old_new_type       cond_old_new_type
          ,CASE 
             WHEN hatc_old_new_type = 'B' THEN 'Both'
             WHEN hatc_old_new_type = 'O' THEN 'Old Value'
             WHEN hatc_old_new_type = 'N' THEN 'New Value'
           END                     old_new_type_descr      
      FROM hig_alert_type_conditions
          ,nm_inv_type_attribs_all
     WHERE hatc_halt_id        = pi_alert_id
       AND hatc_attribute_name = ita_attrib_name
       AND ita_inv_type        = pi_inv_type
    ORDER BY hatc_halt_id, hatc_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_alert_type_conds;                                

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_type_cond(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                               ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                               ,pi_attribute_name       IN     hig_alert_type_attributes.hata_attribute_name%TYPE 
                               ,po_message_severity        OUT hig_codes.hco_code%TYPE
                               ,po_message_cursor          OUT sys_refcursor
                               ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hatc_halt_id            alert_id
          ,hatc_id                 cond_id
          ,hatc_pre_bracket        cond_pre_bracket
          ,hatc_operator           cond_operator
          ,hatc_attribute_name     cond_attribute_name
          ,ita_scrn_text           attribute_name_text
          ,hatc_condition          cond_condition
          ,hatc_attribute_value    cond_attribute_value
          ,awlrs_alerts_api.get_cond_attrib_meaning(pi_inv_type,hatc_attribute_name,hatc_attribute_value) attrib_value_meaning
          ,hatc_post_bracket       cond_post_bracket
          ,hatc_old_new_type       cond_old_new_type
          ,CASE 
             WHEN hatc_old_new_type = 'B' THEN 'Both'
             WHEN hatc_old_new_type = 'O' THEN 'Old Value'
             WHEN hatc_old_new_type = 'N' THEN 'New Value'
           END                     old_new_type_descr
      FROM hig_alert_type_conditions
          ,nm_inv_type_attribs_all
     WHERE hatc_halt_id        = pi_alert_id
       AND hatc_attribute_name = pi_attribute_name
       AND hatc_attribute_name = ita_attrib_name
       AND ita_inv_type        = pi_inv_type
    ORDER BY hatc_halt_id, hatc_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_alert_type_cond;                                                       

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_alert_type_conds(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                                      ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                                      ,pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                      ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                      ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                      ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                      ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                      ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                      ,pi_skip_n_rows          IN     PLS_INTEGER
                                      ,pi_pagesize             IN     PLS_INTEGER
                                      ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                      ,po_message_cursor          OUT sys_refcursor
                                      ,po_cursor                  OUT sys_refcursor)
  IS
    --
    lv_order_by         nm3type.max_varchar2;
    lv_filter           nm3type.max_varchar2;
    --
    lv_cursor_sql  nm3type.max_varchar2 :='SELECT hatc_halt_id            alert_id'
                                              ||',hatc_id                 cond_id'
                                              ||',hatc_pre_bracket        cond_pre_bracket'
                                              ||',hatc_operator           cond_operator'
                                              ||',hatc_attribute_name     cond_attribute_name'
                                              ||',ita_scrn_text           attribute_name_text'
                                              ||',hatc_condition          cond_condition'
                                              ||',hatc_attribute_value    cond_attribute_value'
                                              ||',awlrs_alerts_api.get_cond_attrib_meaning(ita_inv_type,hatc_attribute_name,hatc_attribute_value) attrib_value_meaning'
                                              ||',hatc_post_bracket       cond_post_bracket'
                                              ||',hatc_old_new_type       cond_old_new_type'
                                              ||',CASE 
                                                     WHEN hatc_old_new_type = ''B'' THEN ''Both''
                                                     WHEN hatc_old_new_type = ''O'' THEN ''Old Value''
                                                     WHEN hatc_old_new_type = ''N'' THEN ''New Value''
                                                   END                     old_new_type_descr' 
                                              ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                         ||' FROM hig_alert_type_conditions'
                                              ||',nm_inv_type_attribs_all'
                                        ||' WHERE hatc_halt_id        = :pi_alert_id'
                                          ||' AND hatc_attribute_name = ita_attrib_name'
                                          ||' AND ita_inv_type        = :pi_inv_type'
    ;
    --
    lt_column_data  awlrs_util.column_data_tab;
    --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'cond_operator'
                                ,pi_query_col    => 'hatc_operator'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'cond_pre_bracket'
                                ,pi_query_col    => 'hatc_pre_bracket'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'attribute_name_text'
                                ,pi_query_col    => 'ita_scrn_text'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'cond_condition'
                                ,pi_query_col    => 'hatc_condition'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'cond_attribute_value'
                                ,pi_query_col    => 'hatc_attribute_value'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'attrib_value_meaning'
                                ,pi_query_col    => 'awlrs_alerts_api.get_cond_attrib_meaning(ita_inv_type,hatc_attribute_name,hatc_attribute_value)'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'cond_post_bracket'
                                ,pi_query_col    => 'hatc_post_bracket'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'old_new_type_descr'
                                ,pi_query_col    => 'CASE 
                                                      WHEN hatc_old_new_type = ''B'' THEN ''Both''
                                                      WHEN hatc_old_new_type = ''O'' THEN ''Old Value''
                                                      WHEN hatc_old_new_type = ''N'' THEN ''New Value''
                                                     END'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'hatc_halt_id, hatc_id')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql
    USING pi_alert_id
         ,pi_inv_type
    ;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_alert_type_conds;                                       
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_recipients(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                               ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                               ,po_message_severity        OUT hig_codes.hco_code%TYPE
                               ,po_message_cursor          OUT sys_refcursor
                               ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hatr_halt_id            alert_id
          ,hatr_id                 recip_id
          ,hatr_type               recip_type
          ,hatr_harr_id            recip_rule_id
          ,CASE
              WHEN hatr_harr_id IS NOT NULL AND harr_label IS NOT NULL THEN harr_label
              WHEN hatr_harr_id IS NOT NULL AND harr_label IS NULL
                THEN
                   awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                   ,pi_ita_attrib_name => harr_attribute_name)
           END                     recip_rule_descr 
          ,hatr_nmu_id             recip_user_id
          ,nmu_name                recip_user_name
          ,hatr_nmg_id             recip_group_id
          ,nmg_name                recip_group_name
      FROM hig_alert_type_recipients
          ,hig_alert_recipient_rules
          ,nm_mail_users
          ,nm_mail_groups
     WHERE hatr_halt_id        = pi_alert_id
       AND hatr_harr_id        = harr_id(+)
       AND hatr_nmu_id         = nmu_id(+)
       AND hatr_nmg_id         = nmg_id(+)
    ORDER BY hatr_type desc;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_recipients;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_mail_recipients(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                                     ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                                     ,pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                     ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                     ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                     ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                     ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                     ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                     ,pi_skip_n_rows          IN     PLS_INTEGER
                                     ,pi_pagesize             IN     PLS_INTEGER
                                     ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                     ,po_message_cursor          OUT sys_refcursor
                                     ,po_cursor                  OUT sys_refcursor)
  IS
    --
    lv_order_by         nm3type.max_varchar2;
    lv_filter           nm3type.max_varchar2;
    --
    lv_cursor_sql  nm3type.max_varchar2 :='SELECT hatr_halt_id            alert_id'
                                              ||',hatr_id                 recip_id'
                                              ||',hatr_type               recip_type'
                                              ||',hatr_harr_id            recip_rule_id'
                                              ||',CASE
                                                   WHEN hatr_harr_id IS NOT NULL AND harr_label IS NOT NULL THEN harr_label
                                                   WHEN hatr_harr_id IS NOT NULL AND harr_label IS NULL
                                                     THEN
                                                       awlrs_alerts_api.get_screen_text(halt_nit_inv_type,harr_attribute_name)
                                                 END                      recip_rule_descr'
                                              ||',hatr_nmu_id             recip_user_id'
                                              ||',nmu_name                recip_user_name'
                                              ||',hatr_nmg_id             recip_group_id'
                                              ||',nmg_name                recip_group_name'
                                              ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                         ||' FROM hig_alert_type_recipients'
                                              ||',hig_alert_recipient_rules'
                                              ||',hig_alert_types'
                                              ||',nm_mail_users'
                                              ||',nm_mail_groups'
                                        ||' WHERE hatr_halt_id  = :pi_alert_id'
                                          ||' AND hatr_halt_id  = halt_id'
                                          ||' AND halt_nit_inv_type = :pi_inv_type' 
                                          ||' AND hatr_harr_id  = harr_id(+)'
                                          ||' AND hatr_nmu_id   = nmu_id(+)'
                                          ||' AND hatr_nmg_id   = nmg_id(+)'
    ;
    --
    lt_column_data  awlrs_util.column_data_tab;
    --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'recip_type'
                                ,pi_query_col    => 'hatr_type'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'recip_rule_descr'
                                ,pi_query_col    => 'CASE
                                                      WHEN hatr_harr_id IS NOT NULL AND harr_label IS NOT NULL THEN harr_label
                                                      WHEN hatr_harr_id IS NOT NULL AND harr_label IS NULL
                                                      THEN
                                                       awlrs_alerts_api.get_screen_text(halt_nit_inv_type,harr_attribute_name)
                                                    END'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'recip_user_name'
                                ,pi_query_col    => 'nmu_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'recip_group_name'
                                ,pi_query_col    => 'nmg_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'hatr_type desc')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql
    USING pi_alert_id
         ,pi_inv_type
    ;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_mail_recipients;       
                                                                       
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_details(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                            ,pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                            ,po_message_severity        OUT hig_codes.hco_code%TYPE
                            ,po_message_cursor          OUT sys_refcursor
                            ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR                         
    SELECT hatm_halt_id            alert_id
          ,hatm_id                 mail_id
          ,hatm_mail_from          mail_from
          ,hatm_subject            mail_subject
          ,hatm_mail_text          mail_text
          ,hatm_mail_type          mail_type
          ,hatm_param_1            param_1_code
          ,CASE WHEN hatm_param_1 IS NOT NULL AND hatm_p1_derived = 'Y' THEN hatm_param_1
                WHEN hatm_param_1 IS NOT NULL AND hatm_p1_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_1)
           END                     param_1_descr
          ,hatm_p1_derived         param_1_derived
          ,hatm_param_2            param_2
          ,CASE WHEN hatm_param_2 IS NOT NULL AND hatm_p2_derived = 'Y' THEN hatm_param_2
                WHEN hatm_param_2 IS NOT NULL AND hatm_p2_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_2)
           END                     param_2_descr
          ,hatm_p2_derived         param_2_derived
          ,hatm_param_3            param_3
          ,CASE WHEN hatm_param_3 IS NOT NULL AND hatm_p3_derived = 'Y' THEN hatm_param_3
                WHEN hatm_param_3 IS NOT NULL AND hatm_p3_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_3)
           END                     param_3_descr
          ,hatm_p3_derived         param_3_derived 
          ,hatm_param_4            param_4_code
          ,CASE WHEN hatm_param_4 IS NOT NULL AND hatm_p4_derived = 'Y' THEN hatm_param_4
                WHEN hatm_param_4 IS NOT NULL AND hatm_p4_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_4)
           END                     param_4_descr
          ,hatm_p4_derived         param_4_derived 
          ,hatm_param_5            param_5
          ,CASE WHEN hatm_param_5 IS NOT NULL AND hatm_p5_derived = 'Y' THEN hatm_param_5
                WHEN hatm_param_5 IS NOT NULL AND hatm_p5_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_5)
           END                     param_5_descr
          ,hatm_p5_derived         param_5_derived 
          ,hatm_param_6            param_6
          ,CASE WHEN hatm_param_6 IS NOT NULL AND hatm_p6_derived = 'Y' THEN hatm_param_6
                WHEN hatm_param_6 IS NOT NULL AND hatm_p6_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_6)
           END                     param_6_descr
          ,hatm_p6_derived         param_6_derived 
          ,hatm_param_7            param_7
          ,CASE WHEN hatm_param_7 IS NOT NULL AND hatm_p7_derived = 'Y' THEN hatm_param_7
                WHEN hatm_param_7 IS NOT NULL AND hatm_p7_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_7)
           END                     param_7_descr
          ,hatm_p7_derived         param_7_derived 
          ,hatm_param_8            param_8
          ,CASE WHEN hatm_param_8 IS NOT NULL AND hatm_p8_derived = 'Y' THEN hatm_param_8
                WHEN hatm_param_8 IS NOT NULL AND hatm_p8_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_8)
           END                     param_8_descr
          ,hatm_p8_derived         param_8_derived 
          ,hatm_param_9            param_9
          ,CASE WHEN hatm_param_9 IS NOT NULL AND hatm_p9_derived = 'Y' THEN hatm_param_9
                WHEN hatm_param_9 IS NOT NULL AND hatm_p9_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_9)
           END                     param_9_descr  
          ,hatm_p9_derived         param_9_derived 
          ,hatm_param_10           param_10
          ,CASE WHEN hatm_param_10 IS NOT NULL AND hatm_p10_derived = 'Y' THEN hatm_param_10
                WHEN hatm_param_10 IS NOT NULL AND hatm_p10_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_10)
           END                     param_10_descr
          ,hatm_p10_derived        param_10_derived 
          ,hatm_param_11           param_11
          ,CASE WHEN hatm_param_11 IS NOT NULL AND hatm_p11_derived = 'Y' THEN hatm_param_11
                WHEN hatm_param_11 IS NOT NULL AND hatm_p11_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_11)
           END                     param_11_descr
          ,hatm_p11_derived        param_11_derived 
          ,hatm_param_12           param_12
          ,CASE WHEN hatm_param_12 IS NOT NULL AND hatm_p12_derived = 'Y' THEN hatm_param_12
                WHEN hatm_param_12 IS NOT NULL AND hatm_p12_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_12)
           END                     param_12_descr
          ,hatm_p12_derived        param_12_derived 
          ,hatm_param_13           param_13
          ,CASE WHEN hatm_param_13 IS NOT NULL AND hatm_p13_derived = 'Y' THEN hatm_param_13
                WHEN hatm_param_13 IS NOT NULL AND hatm_p13_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_13)
           END                     param_13_descr
          ,hatm_p13_derived        param_13_derived 
          ,hatm_param_14           param_14
          ,CASE WHEN hatm_param_14 IS NOT NULL AND hatm_p14_derived = 'Y' THEN hatm_param_14
                WHEN hatm_param_14 IS NOT NULL AND hatm_p14_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_14)
           END                     param_14_descr
          ,hatm_p14_derived        param_14_derived 
          ,hatm_param_15           param_15
          ,CASE WHEN hatm_param_15 IS NOT NULL AND hatm_p15_derived = 'Y' THEN hatm_param_15
                WHEN hatm_param_15 IS NOT NULL AND hatm_p15_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_15)
           END                     param_15_descr
          ,hatm_p15_derived        param_15_derived 
          ,hatm_param_16           param_16
          ,CASE WHEN hatm_param_16 IS NOT NULL AND hatm_p16_derived = 'Y' THEN hatm_param_16
                WHEN hatm_param_16 IS NOT NULL AND hatm_p16_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_16)
           END                     param_16_descr
          ,hatm_p16_derived        param_16_derived 
          ,hatm_param_17           param_17
          ,CASE WHEN hatm_param_17 IS NOT NULL AND hatm_p17_derived = 'Y' THEN hatm_param_17
                WHEN hatm_param_17 IS NOT NULL AND hatm_p17_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_17)
           END                     param_17_descr
          ,hatm_p17_derived        param_17_derived 
          ,hatm_param_18           param_18
          ,CASE WHEN hatm_param_18 IS NOT NULL AND hatm_p18_derived = 'Y' THEN hatm_param_18
                WHEN hatm_param_18 IS NOT NULL AND hatm_p18_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_18)
           END                     param_18_descr
          ,hatm_p18_derived        param_18_derived 
          ,hatm_param_19           param_19
          ,CASE WHEN hatm_param_19 IS NOT NULL AND hatm_p19_derived = 'Y' THEN hatm_param_19
                WHEN hatm_param_19 IS NOT NULL AND hatm_p19_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_19)
           END                     param_19_descr
          ,hatm_p19_derived        param_19_derived 
          ,hatm_param_20           param_20   
          ,CASE WHEN hatm_param_20 IS NOT NULL AND hatm_p20_derived = 'Y' THEN hatm_param_20
                WHEN hatm_param_20 IS NOT NULL AND hatm_p20_derived <> 'Y' 
                  THEN awlrs_alerts_api.get_screen_text(pi_ita_inv_type    => pi_inv_type
                                                       ,pi_ita_attrib_name => hatm_param_20)
           END                     param_20_descr
          ,hatm_p20_derived        param_20_derived 
      FROM hig_alert_type_mail     
     WHERE hatm_halt_id        =  pi_alert_id;
  --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_details;   
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_asset_types_lov(po_message_severity    OUT  hig_codes.hco_code%TYPE
                               ,po_message_cursor      OUT  sys_refcursor
                               ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nit_inv_type
          ,nit_descr 
          ,nit_table_name
      FROM all_tables 
          ,nm_inv_types
     WHERE OWNER = sys_context('NM3CORE','APPLICATION_OWNER')
       AND table_name NOT LIKE 'HIG_AUDIT%'
       AND table_name = nit_table_name  
       AND table_name NOT IN ('NM_ELEMENTS_ALL','NM_INV_ITEMS_ALL','HIG_OPTION_VALUES')
    ORDER BY nit_inv_type;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_asset_types_lov;                               
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_ops_lov(po_message_severity    OUT  hig_codes.hco_code%TYPE
                             ,po_message_cursor      OUT  sys_refcursor
                             ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT code 
        ,code descr 
    FROM( 
         SELECT 'Insert' code 
               ,1        ind 
          FROM Dual
        UNION
        SELECT 'Update'   code
               ,2        ind 
          FROM Dual
        UNION
        SELECT 'Delete'  code
               ,3        ind 
          FROM Dual
        )   
    ORDER BY ind;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_alert_ops_lov;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_type_attribs_lov(pi_inv_type          IN     hig_alert_types.halt_nit_inv_type%TYPE
                                      ,po_message_severity    OUT  hig_codes.hco_code%TYPE
                                      ,po_message_cursor      OUT  sys_refcursor
                                      ,po_cursor              OUT  sys_refcursor)
  IS
  --
  lv_query      nm3type.max_varchar2;
  lv_dummy_qry  nm_inv_type_attribs.ita_query%TYPE  := 'SELECT NULL code, NULL descr, NULL value  FROM DUAL WHERE 1=2';
  --
  BEGIN
    --
    lv_query := nm3gaz_qry.get_ngqa_lov_sql(pi_ngqt_item_type_type => 'I'
                                           ,pi_ngqt_item_type      => pi_inv_type);
    -- 
    IF lv_query IS NOT NULL 
      THEN   
        OPEN po_cursor FOR lv_query;
    ELSE
        --return an empty cursor
        OPEN po_cursor FOR lv_dummy_qry;
    null;  
    END IF;                                
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_alert_type_attribs_lov;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_attrib_values_lov(pi_inv_type          IN     hig_alert_types.halt_nit_inv_type%TYPE
                                 ,pi_attrib_name       IN     hig_alert_type_conditions.hatc_attribute_value%TYPE
                                 ,po_message_severity    OUT  hig_codes.hco_code%TYPE
                                 ,po_message_cursor      OUT  sys_refcursor
                                 ,po_cursor              OUT  sys_refcursor)   
  IS
  --
  lv_ita_query  nm_inv_type_attribs.ita_query%TYPE;
  lv_dummy_qry  nm_inv_type_attribs.ita_query%TYPE  := 'SELECT NULL code, NULL descr, NULL value  FROM DUAL WHERE 1=2';
  --
  BEGIN
    --
    lv_ita_query := nm3gaz_qry.get_ngqv_lov_sql(pi_ngqt_item_type_type => 'I'
                                               ,pi_ngqt_item_type      => pi_inv_type
                                               ,pi_ngqa_attrib_name    => pi_attrib_name);
    --
    IF lv_ita_query IS NULL
      THEN
       lv_ita_query := nm3get.get_ita(pi_ita_inv_type    =>  pi_inv_type
                                     ,pi_ita_attrib_name =>  pi_attrib_name
                                     ,pi_raise_not_found =>  FALSE).ita_query;
    END IF;                                         
    --                                         
    IF lv_ita_query IS NOT NULL 
      THEN   
        OPEN po_cursor FOR lv_ita_query;
    ELSE
        --return an empty cursor
        OPEN po_cursor FOR lv_dummy_qry;
    null;  
    END IF;                                
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_attrib_values_lov;     
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_attrib_old_new_lov(pi_operation         IN     hig_alert_types.halt_operation%TYPE
                                  ,po_message_severity    OUT  hig_codes.hco_code%TYPE
                                  ,po_message_cursor      OUT  sys_refcursor
                                  ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Operation'
                               ,pi_parameter_value => pi_operation);
    --                           
    IF pi_operation = 'Insert'
       THEN
        OPEN po_cursor FOR
        SELECT 'N'         code
              ,'New Value' code_descr
          FROM dual;
    ELSIF      
       pi_operation = 'Delete'
       THEN
        OPEN po_cursor FOR
        SELECT 'O'         code
              ,'Old Value' code_descr
          FROM dual;
    ELSIF      
       pi_operation = 'Update'
           THEN
        OPEN po_cursor FOR
        SELECT 'B'         code 
              ,'Both'      code_descr 
          FROM dual
        UNION  
        SELECT 'O'
              ,'Old Value' 
          FROM dual
        UNION  
        SELECT 'N'
              ,'New Value' 
          FROM dual;    
    END IF;            
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_attrib_old_new_lov;
                                                                                                      
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_trigger_alert(pi_inv_type              IN     hig_alert_types.halt_nit_inv_type%TYPE
                                ,pi_table_name            IN     hig_alert_types.halt_table_name%TYPE
                                ,pi_descr                 IN     hig_alert_types.halt_description%TYPE 
                                ,pi_operation             IN     hig_alert_types.halt_operation%TYPE
                                ,pi_immediate             IN     hig_alert_types.halt_immediate%TYPE
                                ,pi_batch_email_threshold IN     hig_alert_types.halt_trigger_count%TYPE
                                ,pi_batch_email_freq      IN     hig_alert_types.halt_frequency_id%TYPE
                                ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT create_trg_alert_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Inv Type'
                               ,pi_parameter_value => pi_inv_type);
    --
    awlrs_util.validate_yn(pi_parameter_desc  => 'Immediate Email'
                          ,pi_parameter_value => pi_immediate);
    --
    IF INITCAP(pi_operation) NOT IN ('Insert','Update','Delete')
       THEN
         hig.raise_ner(pi_appl               => 'HIG'
                      ,pi_id                 =>  70
                      ,pi_supplementary_info => 'Allowable values are Insert, Update and Delete');      
    END IF;                  
    --
    IF pi_immediate = 'N'
      THEN
        awlrs_util.validate_notnull(pi_parameter_desc  => 'Batch Email Frequency'
                                   ,pi_parameter_value => pi_batch_email_freq);
        --   
    END IF;  
    /*
    ||insert into hig_alert_types.
    */
    INSERT
      INTO hig_alert_types
          (halt_id
          ,halt_alert_type
          ,halt_nit_inv_type
          ,halt_table_name
          ,halt_description
          ,halt_operation
          ,halt_immediate
          ,halt_trigger_count
          ,halt_frequency_id
          ,halt_suspend_query
          )
    VALUES (halt_id_seq.NEXTVAL
           ,'T'
           ,pi_inv_type 
           ,pi_table_name
           ,pi_descr
           ,pi_operation
           ,pi_immediate
           ,pi_batch_email_threshold
           ,pi_batch_email_freq
           ,'N'
           );
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_trg_alert_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_trigger_alert;                         
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_trigger_alert(pi_old_alert_id              IN     hig_alert_types.halt_id%TYPE
                                ,pi_old_inv_type              IN     hig_alert_types.halt_nit_inv_type%TYPE
                                ,pi_old_descr                 IN     hig_alert_types.halt_description%TYPE
                                ,pi_old_operation             IN     hig_alert_types.halt_operation%TYPE 
                                ,pi_old_immediate             IN     hig_alert_types.halt_immediate%TYPE
                                ,pi_old_table_name            IN     hig_alert_types.halt_table_name%TYPE 
                                ,pi_old_trigger_name          IN     hig_alert_types.halt_trigger_name%TYPE
                                ,pi_old_batch_email_threshold IN     hig_alert_types.halt_trigger_count%TYPE
                                ,pi_old_batch_email_freq      IN     hig_alert_types.halt_frequency_id%TYPE
                                ,pi_new_descr                 IN     hig_alert_types.halt_description%TYPE                            
                                ,pi_new_immediate             IN     hig_alert_types.halt_immediate%TYPE
                                ,pi_new_batch_email_threshold IN     hig_alert_types.halt_trigger_count%TYPE
                                ,pi_new_batch_email_freq      IN     hig_alert_types.halt_frequency_id%TYPE
                                ,po_trigger_dropped              OUT varchar2
                                ,po_message_severity             OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor               OUT sys_refcursor)
  IS
    --
    lr_db_rec        hig_alert_types%ROWTYPE;
    lv_upd           varchar2(1) := 'N';
    lv_error_text    varchar2(32767);
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_alert_types
       WHERE halt_id = pi_old_alert_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Alert Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_trg_alert_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_yn(pi_parameter_desc  => 'Immediate Email'
                          ,pi_parameter_value => pi_new_immediate);
    --
    IF pi_new_immediate = 'N'
      THEN
        awlrs_util.validate_notnull(pi_parameter_desc  => 'Batch Email Frequency'
                                   ,pi_parameter_value => pi_new_batch_email_freq);
        --   
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.halt_id != pi_old_alert_id
     OR (lr_db_rec.halt_id IS NULL AND pi_old_alert_id IS NOT NULL)
     OR (lr_db_rec.halt_id IS NOT NULL AND pi_old_alert_id IS NULL)
     --
     OR (lr_db_rec.halt_nit_inv_type != pi_old_inv_type)
     OR (lr_db_rec.halt_nit_inv_type IS NULL AND pi_old_inv_type IS NOT NULL)
     OR (lr_db_rec.halt_nit_inv_type IS NOT NULL AND pi_old_inv_type IS NULL)
     --
     OR (UPPER(lr_db_rec.halt_description) != UPPER(pi_old_descr))
     OR (UPPER(lr_db_rec.halt_description) IS NULL AND UPPER(pi_old_descr) IS NOT NULL)
     OR (UPPER(lr_db_rec.halt_description) IS NOT NULL AND UPPER(pi_old_descr) IS NULL)
     --
     OR (UPPER(lr_db_rec.halt_operation) != UPPER(pi_old_operation))
     OR (UPPER(lr_db_rec.halt_operation) IS NULL AND UPPER(pi_old_operation) IS NOT NULL)
     OR (UPPER(lr_db_rec.halt_operation) IS NOT NULL AND UPPER(pi_old_operation) IS NULL)
     --
     OR (lr_db_rec.halt_immediate != pi_old_immediate)
     OR (lr_db_rec.halt_immediate IS NULL AND pi_old_immediate IS NOT NULL)
     OR (lr_db_rec.halt_immediate IS NOT NULL AND pi_old_immediate IS NULL)
     --
     OR (lr_db_rec.halt_table_name != pi_old_table_name)
     OR (lr_db_rec.halt_table_name IS NULL AND pi_old_table_name IS NOT NULL)
     OR (lr_db_rec.halt_table_name IS NOT NULL AND pi_old_table_name IS NULL)
     --
     OR (lr_db_rec.halt_trigger_name != pi_old_trigger_name)
     OR (lr_db_rec.halt_trigger_name IS NULL AND pi_old_trigger_name IS NOT NULL)
     OR (lr_db_rec.halt_trigger_name IS NOT NULL AND pi_old_trigger_name IS NULL)
     --
     OR (lr_db_rec.halt_trigger_count != pi_old_batch_email_threshold)
     OR (lr_db_rec.halt_trigger_count IS NULL AND pi_old_batch_email_threshold IS NOT NULL)
     OR (lr_db_rec.halt_trigger_count IS NOT NULL AND pi_old_batch_email_threshold IS NULL)
     --
     OR (lr_db_rec.halt_frequency_id != pi_old_batch_email_freq)
     OR (lr_db_rec.halt_frequency_id IS NULL AND pi_old_batch_email_freq IS NOT NULL)
     OR (lr_db_rec.halt_frequency_id IS NOT NULL AND pi_old_batch_email_freq IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF UPPER(pi_old_descr) != UPPER(pi_new_descr)
       OR (UPPER(pi_old_descr) IS NULL AND UPPER(pi_new_descr) IS NOT NULL)
       OR (UPPER(pi_old_descr) IS NOT NULL AND UPPER(pi_new_descr) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_immediate != pi_new_immediate
       OR (pi_old_immediate IS NULL AND pi_new_immediate IS NOT NULL)
       OR (pi_old_immediate IS NOT NULL AND pi_new_immediate IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_batch_email_threshold != pi_new_batch_email_threshold
       OR (pi_old_batch_email_threshold IS NULL AND pi_new_batch_email_threshold IS NOT NULL)
       OR (pi_old_batch_email_threshold IS NOT NULL AND pi_new_batch_email_threshold IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_batch_email_freq != pi_new_batch_email_freq
       OR (pi_old_batch_email_freq IS NULL AND pi_new_batch_email_freq IS NOT NULL)
       OR (pi_old_batch_email_freq IS NOT NULL AND pi_new_batch_email_freq IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_alert_types
           SET halt_description   = pi_new_descr
              ,halt_immediate     = pi_new_immediate
              ,halt_trigger_count = pi_new_batch_email_threshold
              ,halt_frequency_id  = pi_new_batch_email_freq
         WHERE halt_id            = pi_old_alert_id;          
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF; 
    END IF;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_old_alert_id
                             ,pi_trigger_name  => pi_old_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_trg_alert_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_trigger_alert;                                 
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION alert_exists(pi_halt_id    IN     hig_alert_types.halt_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM hig_alert_types
     WHERE halt_id = pi_halt_id;
     
    RETURN (lv_cnt > 0);  
    --
  END alert_exists;
                             
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_trigger_alert(pi_alert_id              IN     hig_alert_types.halt_id%TYPE
                                ,pi_trigger_name          IN     hig_alert_types.halt_trigger_name%TYPE
                                ,po_trigger_dropped          OUT varchar2
                                ,po_message_severity         OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor           OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT delete_trg_alert_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    IF NOT alert_exists(pi_halt_id => pi_alert_id) --<> 'Y'
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Alert Id:  '||pi_alert_id);
    END IF;
    --
    /*
    ||delete from hig_alert_type_attributes.
    */
    DELETE 
      FROM hig_alert_type_attributes
     WHERE hata_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_type_conditions.
    */
    DELETE 
      FROM hig_alert_type_conditions
     WHERE hatc_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_type_mail.
    */
    DELETE 
      FROM hig_alert_type_mail
     WHERE hatm_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_type_recipients.
    */
    DELETE 
      FROM hig_alert_type_recipients
     WHERE hatr_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_recipients.
    */
    DELETE 
      FROM hig_alert_recipients
     WHERE har_hal_id in (SELECT hal_id
                           FROM hig_alerts
                          WHERE hal_halt_id = pi_alert_id);
    
    /*
    ||delete from hig_alerts.
    */
    DELETE 
      FROM hig_alerts
     WHERE hal_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_types.
    */
    DELETE 
      FROM hig_alert_types
     WHERE halt_id = pi_alert_id;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_trg_alert_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_trigger_alert;                                   
                                
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION attribute_exists(pi_alert_id      IN   hig_alert_type_attributes.hata_halt_id%TYPE
                           ,pi_attrib_name   IN   hig_alert_type_attributes.hata_attribute_name%TYPE)  
    RETURN BOOLEAN
  IS
    lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*)
      INTO lv_cnt
      FROM hig_alert_type_attributes
     WHERE hata_halt_id               = pi_alert_id 
       AND UPPER(hata_attribute_name) = UPPER(pi_attrib_name);
    --
    RETURN (lv_cnt > 0);
    --
  END attribute_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION attribute_exists(pi_attrib_id    IN   hig_alert_type_attributes.hata_id%TYPE)                             
  RETURN BOOLEAN
  IS
    lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*)
      INTO lv_cnt
      FROM hig_alert_type_attributes
     WHERE hata_id = pi_attrib_id; 
    --
    RETURN (lv_cnt > 0);  
    --
  END attribute_exists;
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_trigger_attributes(pi_alert_id             IN     hig_alert_type_attributes.hata_halt_id%TYPE
                                     ,pi_operation            IN     hig_alert_types.halt_operation%TYPE
                                     ,pi_attribute_name       IN     hig_alert_type_attributes.hata_attribute_name%TYPE  
                                     ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                     ,po_trigger_dropped         OUT varchar2
                                     ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                     ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT create_trg_attrib_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attribute'
                               ,pi_parameter_value => pi_attribute_name);
    --
    IF INITCAP(pi_operation) <> 'Update'
       THEN
         hig.raise_ner(pi_appl               => 'HIG'
                      ,pi_id                 =>  110
                      ,pi_supplementary_info => 'Attributes can only be added for operations set for Update and not '||pi_operation);      
    END IF;                  
    --
    IF attribute_exists(pi_alert_id    => pi_alert_id
                       ,pi_attrib_name => pi_attribute_name) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'Attribute:'||pi_attribute_name);
    END IF;
    --
    /*
    ||insert into hig_alert_type_attributes.
    */
    INSERT
      INTO hig_alert_type_attributes
          (hata_id
          ,hata_halt_id
          ,hata_attribute_name
          )
    VALUES (hata_id_seq.NEXTVAL
           ,pi_alert_id
           ,pi_attribute_name 
           );
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_trg_attrib_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_trigger_attributes;                                                                     

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_trigger_attributes(pi_old_attrib_id        IN     hig_alert_type_attributes.hata_id%TYPE
                                     ,pi_old_alert_id         IN     hig_alert_type_attributes.hata_halt_id%TYPE
                                     ,pi_old_attribute_name   IN     hig_alert_type_attributes.hata_attribute_name%TYPE
                                     ,pi_new_attrib_id        IN     hig_alert_type_attributes.hata_id%TYPE
                                     ,pi_new_alert_id         IN     hig_alert_type_attributes.hata_halt_id%TYPE
                                     ,pi_new_attribute_name   IN     hig_alert_type_attributes.hata_attribute_name%TYPE  
                                     ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                     ,po_trigger_dropped         OUT varchar2
                                     ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                     ,po_message_cursor          OUT sys_refcursor)
  IS
    --
    lr_db_rec        hig_alert_type_attributes%ROWTYPE;
    lv_upd           varchar2(1) := 'N';
    lv_error_text    varchar2(32767);
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_alert_type_attributes
       WHERE hata_id = pi_old_attrib_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Attrib Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_trg_attrib_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attrib Id'
                               ,pi_parameter_value => pi_new_attrib_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_new_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attribute'
                               ,pi_parameter_value => pi_new_attribute_name);
    --
    IF attribute_exists(pi_alert_id    => pi_old_alert_id
                       ,pi_attrib_name => pi_new_attribute_name) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'Attribute:'||pi_new_attribute_name);
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.hata_id != pi_old_attrib_id
     OR (lr_db_rec.hata_id IS NULL AND pi_old_attrib_id IS NOT NULL)
     OR (lr_db_rec.hata_id IS NOT NULL AND pi_old_attrib_id IS NULL)
     --
     OR (lr_db_rec.hata_halt_id != pi_old_alert_id)
     OR (lr_db_rec.hata_halt_id IS NULL AND pi_old_alert_id IS NOT NULL)
     OR (lr_db_rec.hata_halt_id IS NOT NULL AND pi_old_alert_id IS NULL)
     --
     OR (UPPER(lr_db_rec.hata_attribute_name) != UPPER(pi_old_attribute_name))
     OR (UPPER(lr_db_rec.hata_attribute_name) IS NULL AND UPPER(pi_old_attribute_name) IS NOT NULL)
     OR (UPPER(lr_db_rec.hata_attribute_name) IS NOT NULL AND UPPER(pi_old_attribute_name) IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF UPPER(pi_old_attribute_name) != UPPER(pi_new_attribute_name)
       OR (UPPER(pi_old_attribute_name) IS NULL AND UPPER(pi_new_attribute_name) IS NOT NULL)
       OR (UPPER(pi_old_attribute_name) IS NOT NULL AND UPPER(pi_new_attribute_name) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_alert_type_attributes
           SET hata_attribute_name = UPPER(pi_new_attribute_name)
         WHERE hata_id             = pi_old_attrib_id
           AND hata_halt_id        = pi_old_alert_id;
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF;
    END IF;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_old_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_trg_attrib_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_trigger_attributes;                                      

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_trigger_attributes(pi_attrib_id            IN     hig_alert_type_attributes.hata_id%TYPE
                                     ,pi_alert_id             IN     hig_alert_type_attributes.hata_halt_id%TYPE
                                     ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                     ,po_trigger_dropped         OUT varchar2
                                     ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                     ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT delete_trg_attrib_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attrib Id'
                               ,pi_parameter_value => pi_attrib_id);
    --
    IF NOT attribute_exists(pi_attrib_id => pi_attrib_id) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Attrib Id:  '||pi_attrib_id);
    END IF;
    /*
    ||delete from hig_alert_type_attributes.
    */
    DELETE 
      FROM hig_alert_type_attributes
     WHERE hata_id = pi_attrib_id;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_trg_attrib_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_trigger_attributes;                                                                     
                                     
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_attribute_conditions(pi_alert_id             IN     hig_alert_type_conditions.hatc_halt_id%TYPE
                                       ,pi_operation            IN     hig_alert_types.halt_operation%TYPE
                                       ,pi_operator             IN     hig_alert_type_conditions.hatc_operator%TYPE
                                       ,pi_pre_bracket          IN     hig_alert_type_conditions.hatc_pre_bracket%TYPE
                                       ,pi_attribute_name       IN     hig_alert_type_conditions.hatc_attribute_name%TYPE
                                       ,pi_condition            IN     hig_alert_type_conditions.hatc_condition%TYPE
                                       ,pi_attribute_value      IN     hig_alert_type_conditions.hatc_attribute_value%TYPE
                                       ,pi_post_bracket         IN     hig_alert_type_conditions.hatc_post_bracket%TYPE
                                       ,pi_old_new_type         IN     hig_alert_type_conditions.hatc_old_new_type%TYPE
                                       ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                       ,po_trigger_dropped         OUT varchar2
                                       ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                       ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT create_attrib_conds_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Operator'
                               ,pi_parameter_value => pi_operator);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attribute Name'
                               ,pi_parameter_value => pi_attribute_name);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Condition'
                               ,pi_parameter_value => pi_condition);
    --
    IF INITCAP(pi_operation) = 'Update'
      THEN
        awlrs_util.validate_notnull(pi_parameter_desc  => 'Old/New Type'
                                   ,pi_parameter_value => pi_old_new_type);
    END IF;                               
    --
    /*
    ||insert into hig_alert_type_conditions.
    */
    INSERT
      INTO hig_alert_type_conditions
          (hatc_id
          ,hatc_halt_id
          ,hatc_pre_bracket
          ,hatc_operator
          ,hatc_attribute_name
          ,hatc_condition
          ,hatc_attribute_value
          ,hatc_post_bracket
          ,hatc_old_new_type
          )
    VALUES (hatc_id_seq.NEXTVAL
           ,pi_alert_id
           ,pi_pre_bracket
           ,pi_operator 
           ,pi_attribute_name
           ,pi_condition
           ,pi_attribute_value
           ,pi_post_bracket
           ,CASE 
              WHEN INITCAP(pi_operation) = 'Insert' THEN 'N'
              WHEN INITCAP(pi_operation) = 'Delete' THEN 'O'
              WHEN INITCAP(pi_operation) = 'Update' THEN pi_old_new_type
            END  
           );
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_attrib_conds_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_attribute_conditions;                                           
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_attribute_conditions(pi_operation            IN     hig_alert_types.halt_operation%TYPE
                                       ,pi_old_hatc_id          IN     hig_alert_type_conditions.hatc_id%TYPE
                                       ,pi_old_alert_id         IN     hig_alert_type_conditions.hatc_halt_id%TYPE
                                       ,pi_old_operator         IN     hig_alert_type_conditions.hatc_operator%TYPE
                                       ,pi_old_pre_bracket      IN     hig_alert_type_conditions.hatc_pre_bracket%TYPE
                                       ,pi_old_attribute_name   IN     hig_alert_type_conditions.hatc_attribute_name%TYPE
                                       ,pi_old_condition        IN     hig_alert_type_conditions.hatc_condition%TYPE
                                       ,pi_old_attribute_value  IN     hig_alert_type_conditions.hatc_attribute_value%TYPE
                                       ,pi_old_post_bracket     IN     hig_alert_type_conditions.hatc_post_bracket%TYPE
                                       ,pi_old_old_new_type     IN     hig_alert_type_conditions.hatc_old_new_type%TYPE
                                       ,pi_new_hatc_id          IN     hig_alert_type_conditions.hatc_id%TYPE     
                                       ,pi_new_alert_id         IN     hig_alert_type_conditions.hatc_halt_id%TYPE                                  
                                       ,pi_new_operator         IN     hig_alert_type_conditions.hatc_operator%TYPE
                                       ,pi_new_pre_bracket      IN     hig_alert_type_conditions.hatc_pre_bracket%TYPE
                                       ,pi_new_attribute_name   IN     hig_alert_type_conditions.hatc_attribute_name%TYPE
                                       ,pi_new_condition        IN     hig_alert_type_conditions.hatc_condition%TYPE
                                       ,pi_new_attribute_value  IN     hig_alert_type_conditions.hatc_attribute_value%TYPE
                                       ,pi_new_post_bracket     IN     hig_alert_type_conditions.hatc_post_bracket%TYPE
                                       ,pi_new_old_new_type     IN     hig_alert_type_conditions.hatc_old_new_type%TYPE
                                       ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                       ,po_trigger_dropped         OUT varchar2
                                       ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                       ,po_message_cursor          OUT sys_refcursor)
  IS
    --
    lr_db_rec        hig_alert_type_conditions%ROWTYPE;
    lv_upd           varchar2(1) := 'N';
    lv_error_text    varchar2(32767);
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_alert_type_conditions
       WHERE hatc_id = pi_old_hatc_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_attrib_conds_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_new_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Operator'
                               ,pi_parameter_value => pi_new_operator);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attribute Name'
                               ,pi_parameter_value => pi_new_attribute_name);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Condition'
                               ,pi_parameter_value => pi_new_condition);
    --
    IF INITCAP(pi_operation) = 'Update'
      THEN
        awlrs_util.validate_notnull(pi_parameter_desc  => 'Old/New Type'
                                   ,pi_parameter_value => pi_new_old_new_type);
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.hatc_id != pi_old_hatc_id
     OR (lr_db_rec.hatc_id IS NULL AND pi_old_hatc_id IS NOT NULL)
     OR (lr_db_rec.hatc_id IS NOT NULL AND pi_old_hatc_id IS NULL)
     --
     OR (lr_db_rec.hatc_halt_id != pi_old_alert_id)
     OR (lr_db_rec.hatc_halt_id IS NULL AND pi_old_alert_id IS NOT NULL)
     OR (lr_db_rec.hatc_halt_id IS NOT NULL AND pi_old_alert_id IS NULL)
     --
     OR (lr_db_rec.hatc_operator != pi_old_operator)
     OR (lr_db_rec.hatc_operator IS NULL AND pi_old_operator IS NOT NULL)
     OR (lr_db_rec.hatc_operator IS NOT NULL AND pi_old_operator IS NULL)
     --
     OR (lr_db_rec.hatc_pre_bracket != pi_old_pre_bracket)
     OR (lr_db_rec.hatc_pre_bracket IS NULL AND pi_old_pre_bracket IS NOT NULL)
     OR (lr_db_rec.hatc_pre_bracket IS NOT NULL AND pi_old_pre_bracket IS NULL)
     --
     OR (UPPER(lr_db_rec.hatc_attribute_name) != UPPER(pi_old_attribute_name))
     OR (UPPER(lr_db_rec.hatc_attribute_name) IS NULL AND UPPER(pi_old_attribute_name) IS NOT NULL)
     OR (UPPER(lr_db_rec.hatc_attribute_name) IS NOT NULL AND UPPER(pi_old_attribute_name) IS NULL)
     --
     OR (lr_db_rec.hatc_condition != pi_old_condition)
     OR (lr_db_rec.hatc_condition IS NULL AND pi_old_condition IS NOT NULL)
     OR (lr_db_rec.hatc_condition IS NOT NULL AND pi_old_condition IS NULL)
     --
     OR (UPPER(lr_db_rec.hatc_attribute_value) != UPPER(pi_old_attribute_value))
     OR (UPPER(lr_db_rec.hatc_attribute_value) IS NULL AND UPPER(pi_old_attribute_value) IS NOT NULL)
     OR (UPPER(lr_db_rec.hatc_attribute_value) IS NOT NULL AND UPPER(pi_old_attribute_value) IS NULL)
     --
     OR (lr_db_rec.hatc_post_bracket != pi_old_post_bracket)
     OR (lr_db_rec.hatc_post_bracket IS NULL AND pi_old_post_bracket IS NOT NULL)
     OR (lr_db_rec.hatc_post_bracket IS NOT NULL AND pi_old_post_bracket IS NULL)
     --
     OR (lr_db_rec.hatc_old_new_type != pi_old_old_new_type)
     OR (lr_db_rec.hatc_old_new_type IS NULL AND pi_old_old_new_type IS NOT NULL)
     OR (lr_db_rec.hatc_old_new_type IS NOT NULL AND pi_old_old_new_type IS NULL)
     --
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      
      IF pi_old_hatc_id != pi_new_hatc_id
       OR (pi_old_hatc_id IS NULL AND pi_new_hatc_id IS NOT NULL)
       OR (pi_old_hatc_id IS NOT NULL AND pi_new_hatc_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_alert_id != pi_new_alert_id
       OR (pi_old_alert_id IS NULL AND pi_new_alert_id IS NOT NULL)
       OR (pi_old_alert_id IS NOT NULL AND pi_new_alert_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_operator != pi_new_operator
       OR (pi_old_operator IS NULL AND pi_new_operator IS NOT NULL)
       OR (pi_old_operator IS NOT NULL AND pi_new_operator IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_pre_bracket != pi_new_pre_bracket
       OR (pi_old_pre_bracket IS NULL AND pi_new_pre_bracket IS NOT NULL)
       OR (pi_old_pre_bracket IS NOT NULL AND pi_new_pre_bracket IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_attribute_name) != UPPER(pi_new_attribute_name)
       OR (UPPER(pi_old_attribute_name) IS NULL AND UPPER(pi_new_attribute_name) IS NOT NULL)
       OR (UPPER(pi_old_attribute_name) IS NOT NULL AND UPPER(pi_new_attribute_name) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_condition != pi_new_condition
       OR (pi_old_condition IS NULL AND pi_new_condition IS NOT NULL)
       OR (pi_old_condition IS NOT NULL AND pi_new_condition IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_attribute_value) != UPPER(pi_new_attribute_value)
       OR (UPPER(pi_old_attribute_value) IS NULL AND UPPER(pi_new_attribute_value) IS NOT NULL)
       OR (UPPER(pi_old_attribute_value) IS NOT NULL AND UPPER(pi_new_attribute_value) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_post_bracket != pi_new_post_bracket
       OR (pi_old_post_bracket IS NULL AND pi_new_post_bracket IS NOT NULL)
       OR (pi_old_post_bracket IS NOT NULL AND pi_new_post_bracket IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_old_new_type != pi_new_old_new_type
       OR (pi_old_old_new_type IS NULL AND pi_new_old_new_type IS NOT NULL)
       OR (pi_old_old_new_type IS NOT NULL AND pi_new_old_new_type IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_alert_type_conditions
           SET hatc_operator        = pi_new_operator
              ,hatc_pre_bracket     = pi_new_pre_bracket
              ,hatc_attribute_name  = UPPER(pi_new_attribute_name)
              ,hatc_condition       = pi_new_condition
              ,hatc_attribute_value = UPPER(pi_new_attribute_value)
              ,hatc_post_bracket    = pi_new_post_bracket
              ,hatc_old_new_type    = pi_new_old_new_type
         WHERE hatc_id              = pi_old_hatc_id;          
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF; 
    END IF;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_old_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_attrib_conds_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_attribute_conditions;                                        

  --
  -----------------------------------------------------------------------------
  --
  FUNCTION conditions_exist(pi_hatc_id    IN     hig_alert_type_conditions.hatc_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM hig_alert_type_conditions
     WHERE hatc_id = pi_hatc_id;
    -- 
    RETURN (lv_cnt > 0);  
    --
  END conditions_exist;
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_attribute_conditions(pi_hatc_id              IN     hig_alert_type_conditions.hatc_id%TYPE
                                       ,pi_alert_id             IN     hig_alert_type_conditions.hatc_halt_id%TYPE 
                                       ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                       ,po_trigger_dropped         OUT varchar2
                                       ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                       ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT delete_attrib_conds_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Condition Id'
                               ,pi_parameter_value => pi_hatc_id);
    --
    IF NOT conditions_exist(pi_hatc_id => pi_hatc_id) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Condition Id:  '||pi_hatc_id);
    END IF;
    /*
    ||delete from hig_alert_type_conditions.
    */
    DELETE 
      FROM hig_alert_type_conditions
     WHERE hatc_id = pi_hatc_id;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_attrib_conds_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_attribute_conditions;                                          
  
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE recipient_type_lov(po_message_severity OUT  hig_codes.hco_code%TYPE
                              ,po_message_cursor   OUT  sys_refcursor
                              ,po_cursor           OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT code 
          ,code descr 
          FROM( 
               SELECT 'To :'   code 
                     ,1        ind 
                 FROM Dual
               UNION
               SELECT 'Cc :'   code
                     ,2        ind 
                 FROM Dual
               UNION
               SELECT 'Bcc :'  code
                     ,3        ind 
                 FROM Dual
              )   
    ORDER BY ind;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END recipient_type_lov;                              
                              
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE recipient_lov(pi_inv_type         IN      hig_alert_types.halt_nit_inv_type%TYPE
                         ,po_message_severity    OUT  hig_codes.hco_code%TYPE
                         ,po_message_cursor      OUT  sys_refcursor
                         ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT harr_id
          ,NVL(harr_label,ita_scrn_text) scrn_text
      FROM nm_inv_type_attribs
          ,hig_alert_recipient_rules
     WHERE ita_inv_type = pi_inv_type  
       AND ita_attrib_name = harr_attribute_name 
    ORDER BY harr_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END recipient_lov;                                                        
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE username_recip_lov(po_message_severity OUT  hig_codes.hco_code%TYPE
                              ,po_message_cursor   OUT  sys_refcursor
                              ,po_cursor           OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmu_id
          ,nmu_name
          ,nmu_email_address
      FROM nm_mail_users 
    ORDER BY nmu_name;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END username_recip_lov;                                

  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE group_name_recip_lov(po_message_severity OUT  hig_codes.hco_code%TYPE
                                ,po_message_cursor   OUT  sys_refcursor
                                ,po_cursor           OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT DISTINCT nmg_id
          ,nmg_name 
      FROM nm_mail_group_membership
          ,nm_mail_groups
          ,nm_mail_users
     WHERE  nmgm_nmg_id = nmg_id
       AND  nmgm_nmu_id = nmu_id
    ORDER BY nmg_name;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END group_name_recip_lov;                                  
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_mail_recipient(pi_alert_id             IN     hig_alert_type_recipients.hatr_halt_id%TYPE
                                 ,pi_recipient_type       IN     hig_alert_type_recipients.hatr_type%TYPE
                                 ,pi_recipient            IN     hig_alert_type_recipients.hatr_harr_id%TYPE  
                                 ,pi_user_id              IN     hig_alert_type_recipients.hatr_nmu_id%TYPE
                                 ,pi_group_id             IN     hig_alert_type_recipients.hatr_nmg_id%TYPE
                                 ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                 ,po_trigger_dropped         OUT varchar2
                                 ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT create_mail_recip_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Recipient Type'
                               ,pi_parameter_value => pi_recipient_type);
    --
    IF    pi_recipient IS NULL
      AND pi_user_id   IS NULL
      AND pi_group_id  IS NULL
      THEN
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 22
                     ,pi_supplementary_info => 'Please enter a value in at least one of the Recipient fields');
    END IF;  
    --
    /*
    ||insert into hig_alert_type_recipients.
    */
    INSERT
      INTO hig_alert_type_recipients
          (hatr_id
          ,hatr_halt_id
          ,hatr_type
          ,hatr_harr_id
          ,hatr_nmu_id
          ,hatr_nmg_id
          )
    VALUES (hatr_id_seq.NEXTVAL
           ,pi_alert_id
           ,pi_recipient_type
           ,pi_recipient 
           ,pi_user_id
           ,pi_group_id
           );
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_mail_recip_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_mail_recipient;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_mail_recipient(pi_old_recip_id         IN     hig_alert_type_recipients.hatr_id%TYPE
                                 ,pi_old_alert_id         IN     hig_alert_type_recipients.hatr_halt_id%TYPE
                                 ,pi_old_recipient_type   IN     hig_alert_type_recipients.hatr_type%TYPE
                                 ,pi_old_recipient        IN     hig_alert_type_recipients.hatr_harr_id%TYPE  
                                 ,pi_old_user_id          IN     hig_alert_type_recipients.hatr_nmu_id%TYPE
                                 ,pi_old_group_id         IN     hig_alert_type_recipients.hatr_nmg_id%TYPE
                                 ,pi_new_recip_id         IN     hig_alert_type_recipients.hatr_id%TYPE
                                 ,pi_new_alert_id         IN     hig_alert_type_recipients.hatr_halt_id%TYPE
                                 ,pi_new_recipient_type   IN     hig_alert_type_recipients.hatr_type%TYPE
                                 ,pi_new_recipient        IN     hig_alert_type_recipients.hatr_harr_id%TYPE  
                                 ,pi_new_user_id          IN     hig_alert_type_recipients.hatr_nmu_id%TYPE
                                 ,pi_new_group_id         IN     hig_alert_type_recipients.hatr_nmg_id%TYPE
                                 ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                 ,po_trigger_dropped         OUT varchar2
                                 ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor          OUT sys_refcursor)
  IS
    --
    lr_db_rec        hig_alert_type_recipients%ROWTYPE;
    lv_upd           varchar2(1) := 'N';
    lv_error_text    varchar2(32767);
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_alert_type_recipients
       WHERE hatr_id = pi_old_recip_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Recipient Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_mail_recip_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Recipient Id'
                               ,pi_parameter_value => pi_new_recip_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_new_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Recipient Type'
                               ,pi_parameter_value => pi_new_recipient_type);
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.hatr_id != pi_old_recip_id
     OR (lr_db_rec.hatr_id IS NULL AND pi_old_recip_id IS NOT NULL)
     OR (lr_db_rec.hatr_id IS NOT NULL AND pi_old_recip_id IS NULL)
     --
     OR (lr_db_rec.hatr_halt_id != pi_old_alert_id)
     OR (lr_db_rec.hatr_halt_id IS NULL AND pi_old_alert_id IS NOT NULL)
     OR (lr_db_rec.hatr_halt_id IS NOT NULL AND pi_old_alert_id IS NULL)
     --
     OR (lr_db_rec.hatr_type != pi_old_recipient_type)
     OR (lr_db_rec.hatr_type IS NULL AND pi_old_recipient_type IS NOT NULL)
     OR (lr_db_rec.hatr_type IS NOT NULL AND pi_old_recipient_type IS NULL)
     --
     OR (lr_db_rec.hatr_harr_id != pi_old_recipient)
     OR (lr_db_rec.hatr_harr_id IS NULL AND pi_old_recipient IS NOT NULL)
     OR (lr_db_rec.hatr_harr_id IS NOT NULL AND pi_old_recipient IS NULL)
     --
     OR (lr_db_rec.hatr_nmu_id != pi_old_user_id)
     OR (lr_db_rec.hatr_nmu_id IS NULL AND pi_old_user_id IS NOT NULL)
     OR (lr_db_rec.hatr_nmu_id IS NOT NULL AND pi_old_user_id IS NULL)
     --
     OR (lr_db_rec.hatr_nmg_id != pi_old_group_id)
     OR (lr_db_rec.hatr_nmg_id IS NULL AND pi_old_group_id IS NOT NULL)
     OR (lr_db_rec.hatr_nmg_id IS NOT NULL AND pi_old_group_id IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF pi_old_recipient_type != pi_new_recipient_type
       OR (pi_old_recipient_type IS NULL AND pi_new_recipient_type IS NOT NULL)
       OR (pi_old_recipient_type IS NOT NULL AND pi_new_recipient_type IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_recipient != pi_new_recipient
       OR (pi_old_recipient IS NULL AND pi_new_recipient IS NOT NULL)
       OR (pi_old_recipient IS NOT NULL AND pi_new_recipient IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_user_id != pi_new_user_id
       OR (pi_old_user_id IS NULL AND pi_new_user_id IS NOT NULL)
       OR (pi_old_user_id IS NOT NULL AND pi_new_user_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_group_id != pi_new_group_id
       OR (pi_old_group_id IS NULL AND pi_new_group_id IS NOT NULL)
       OR (pi_old_group_id IS NOT NULL AND pi_new_group_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_alert_type_recipients
           SET hatr_type    = pi_new_recipient_type
              ,hatr_harr_id = pi_new_recipient
              ,hatr_nmu_id  = pi_new_user_id
              ,hatr_nmg_id  = pi_new_group_id
         WHERE hatr_id      = pi_old_recip_id;          
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF; 
    END IF;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_old_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_mail_recip_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_mail_recipient;                                                                     
                                        
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION recipient_exists(pi_hatr_id    IN     hig_alert_type_recipients.hatr_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM hig_alert_type_recipients
     WHERE hatr_id = pi_hatr_id;
     
    RETURN (lv_cnt > 0);  
    --    
  END recipient_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION recipient_exists(pi_hatr_halt_id    IN     hig_alert_type_recipients.hatr_halt_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM hig_alert_type_recipients
     WHERE hatr_halt_id = pi_hatr_halt_id;
     
    RETURN (lv_cnt > 0);  
    --    
  END recipient_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_mail_recipient(pi_recip_id             IN     hig_alert_type_recipients.hatr_id%TYPE
                                 ,pi_alert_id             IN     hig_alert_type_recipients.hatr_halt_id%TYPE                               
                                 ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                                 ,po_trigger_dropped         OUT varchar2 
                                 ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT delete_mail_recip_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Recipient Id'
                               ,pi_parameter_value => pi_recip_id);
    --
    IF NOT recipient_exists(pi_hatr_id => pi_recip_id)
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Recipient Id:  '||pi_recip_id);
    END IF;
    /*
    ||delete from hig_alert_type_recipients.
    */
    DELETE 
      FROM hig_alert_type_recipients
     WHERE hatr_id = pi_recip_id;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_mail_recip_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_mail_recipient;  
  
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE mail_parameter_lov(pi_inv_type          IN     hig_alert_types.halt_nit_inv_type%TYPE
                              ,po_message_severity    OUT  hig_codes.hco_code%TYPE
                              ,po_message_cursor      OUT  sys_refcursor
                              ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT ita_attrib_name
          ,ita_scrn_text
          ,'N' Derived
      FROM nm_inv_type_attribs
     WHERE ita_inv_type = pi_inv_type
    UNION 
    SELECT hatml_screen_text ita_attrib_name
          ,hatml_screen_text 
          ,'Y' derived
      FROM hig_alert_type_mail_lookup
     WHERE hatml_inv_type  = pi_inv_type
    ORDER BY 2;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END mail_parameter_lov;    
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_mail(pi_alert_id          IN     hig_alert_type_mail.hatm_halt_id%TYPE
                       ,pi_mail_subject      IN     hig_alert_type_mail.hatm_subject%TYPE
                       ,pi_mail_text         IN     hig_alert_type_mail.hatm_mail_text%TYPE
                       ,pi_mail_type         IN     hig_alert_type_mail.hatm_mail_type%TYPE
                       ,pi_mail_from         IN     hig_alert_type_mail.hatm_mail_from%TYPE
                       ,pi_param_1           IN     hig_alert_type_mail.hatm_param_1%TYPE
                       ,pi_param_1_derived   IN     hig_alert_type_mail.hatm_p1_derived%TYPE
                       ,pi_param_2           IN     hig_alert_type_mail.hatm_param_2%TYPE
                       ,pi_param_2_derived   IN     hig_alert_type_mail.hatm_p2_derived%TYPE
                       ,pi_param_3           IN     hig_alert_type_mail.hatm_param_3%TYPE
                       ,pi_param_3_derived   IN     hig_alert_type_mail.hatm_p3_derived%TYPE
                       ,pi_param_4           IN     hig_alert_type_mail.hatm_param_4%TYPE
                       ,pi_param_4_derived   IN     hig_alert_type_mail.hatm_p4_derived%TYPE
                       ,pi_param_5           IN     hig_alert_type_mail.hatm_param_5%TYPE
                       ,pi_param_5_derived   IN     hig_alert_type_mail.hatm_p5_derived%TYPE
                       ,pi_param_6           IN     hig_alert_type_mail.hatm_param_6%TYPE
                       ,pi_param_6_derived   IN     hig_alert_type_mail.hatm_p6_derived%TYPE
                       ,pi_param_7           IN     hig_alert_type_mail.hatm_param_7%TYPE
                       ,pi_param_7_derived   IN     hig_alert_type_mail.hatm_p7_derived%TYPE
                       ,pi_param_8           IN     hig_alert_type_mail.hatm_param_8%TYPE
                       ,pi_param_8_derived   IN     hig_alert_type_mail.hatm_p8_derived%TYPE
                       ,pi_param_9           IN     hig_alert_type_mail.hatm_param_9%TYPE
                       ,pi_param_9_derived   IN     hig_alert_type_mail.hatm_p9_derived%TYPE
                       ,pi_param_10          IN     hig_alert_type_mail.hatm_param_10%TYPE
                       ,pi_param_10_derived  IN     hig_alert_type_mail.hatm_p10_derived%TYPE
                       ,pi_param_11          IN     hig_alert_type_mail.hatm_param_11%TYPE
                       ,pi_param_11_derived  IN     hig_alert_type_mail.hatm_p11_derived%TYPE
                       ,pi_param_12          IN     hig_alert_type_mail.hatm_param_12%TYPE
                       ,pi_param_12_derived  IN     hig_alert_type_mail.hatm_p12_derived%TYPE
                       ,pi_param_13          IN     hig_alert_type_mail.hatm_param_13%TYPE
                       ,pi_param_13_derived  IN     hig_alert_type_mail.hatm_p13_derived%TYPE
                       ,pi_param_14          IN     hig_alert_type_mail.hatm_param_14%TYPE
                       ,pi_param_14_derived  IN     hig_alert_type_mail.hatm_p14_derived%TYPE
                       ,pi_param_15          IN     hig_alert_type_mail.hatm_param_15%TYPE
                       ,pi_param_15_derived  IN     hig_alert_type_mail.hatm_p15_derived%TYPE
                       ,pi_param_16          IN     hig_alert_type_mail.hatm_param_16%TYPE
                       ,pi_param_16_derived  IN     hig_alert_type_mail.hatm_p16_derived%TYPE
                       ,pi_param_17          IN     hig_alert_type_mail.hatm_param_17%TYPE
                       ,pi_param_17_derived  IN     hig_alert_type_mail.hatm_p17_derived%TYPE
                       ,pi_param_18          IN     hig_alert_type_mail.hatm_param_18%TYPE
                       ,pi_param_18_derived  IN     hig_alert_type_mail.hatm_p18_derived%TYPE
                       ,pi_param_19          IN     hig_alert_type_mail.hatm_param_19%TYPE
                       ,pi_param_19_derived  IN     hig_alert_type_mail.hatm_p19_derived%TYPE
                       ,pi_param_20          IN     hig_alert_type_mail.hatm_param_20%TYPE
                       ,pi_param_20_derived  IN     hig_alert_type_mail.hatm_p20_derived%TYPE
                       ,pi_trigger_name      IN     hig_alert_types.halt_trigger_name%TYPE
                       ,po_trigger_dropped     OUT varchar2
                       ,po_message_severity    OUT hig_codes.hco_code%TYPE
                       ,po_message_cursor      OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT create_mail_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Mail Subject'
                               ,pi_parameter_value => pi_mail_subject);
    --
    IF NVL(pi_mail_type, 'N') NOT IN ('H','T') THEN
        --
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 30
                     ,pi_supplementary_info => 'Mail Type must be either H (HTML) or T (Plain Text)');
        --
    END IF;
    --
    /*
    ||insert into hig_alert_type_mail.
    */
    INSERT
      INTO hig_alert_type_mail
          (hatm_id
          ,hatm_halt_id
          ,hatm_subject
          ,hatm_mail_text
          ,hatm_mail_type
          ,hatm_mail_from
          ,hatm_param_1
          ,hatm_p1_derived
          ,hatm_param_2
          ,hatm_p2_derived
          ,hatm_param_3
          ,hatm_p3_derived
          ,hatm_param_4
          ,hatm_p4_derived
          ,hatm_param_5
          ,hatm_p5_derived
          ,hatm_param_6
          ,hatm_p6_derived
          ,hatm_param_7
          ,hatm_p7_derived
          ,hatm_param_8
          ,hatm_p8_derived
          ,hatm_param_9
          ,hatm_p9_derived
          ,hatm_param_10
          ,hatm_p10_derived
          ,hatm_param_11
          ,hatm_p11_derived
          ,hatm_param_12
          ,hatm_p12_derived
          ,hatm_param_13
          ,hatm_p13_derived
          ,hatm_param_14
          ,hatm_p14_derived
          ,hatm_param_15
          ,hatm_p15_derived
          ,hatm_param_16
          ,hatm_p16_derived
          ,hatm_param_17
          ,hatm_p17_derived
          ,hatm_param_18
          ,hatm_p18_derived
          ,hatm_param_19
          ,hatm_p19_derived
          ,hatm_param_20
          ,hatm_p20_derived
          )
    VALUES (hatm_id_seq.NEXTVAL
           ,pi_alert_id
           ,pi_mail_subject
           ,pi_mail_text 
           ,pi_mail_type
           ,pi_mail_from
           ,pi_param_1
           ,pi_param_1_derived
           ,pi_param_2
           ,pi_param_2_derived
           ,pi_param_3
           ,pi_param_3_derived
           ,pi_param_4
           ,pi_param_4_derived
           ,pi_param_5
           ,pi_param_5_derived
           ,pi_param_6
           ,pi_param_6_derived
           ,pi_param_7
           ,pi_param_7_derived
           ,pi_param_8
           ,pi_param_8_derived
           ,pi_param_9
           ,pi_param_9_derived
           ,pi_param_10
           ,pi_param_10_derived
           ,pi_param_11
           ,pi_param_11_derived
           ,pi_param_12
           ,pi_param_12_derived
           ,pi_param_13
           ,pi_param_13_derived
           ,pi_param_14
           ,pi_param_14_derived
           ,pi_param_15
           ,pi_param_15_derived
           ,pi_param_16
           ,pi_param_16_derived
           ,pi_param_17
           ,pi_param_17_derived
           ,pi_param_18
           ,pi_param_18_derived
           ,pi_param_19
           ,pi_param_19_derived
           ,pi_param_20
           ,pi_param_20_derived
           );
    --
   --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_mail_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_mail;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_mail(pi_alert_id         IN     hig_alert_type_mail.hatm_halt_id%TYPE
                       ,pi_mail_subject     IN     hig_alert_type_mail.hatm_subject%TYPE
                       ,pi_mail_text        IN     hig_alert_type_mail.hatm_mail_text%TYPE
                       ,pi_mail_type        IN     hig_alert_type_mail.hatm_mail_type%TYPE
                       ,pi_mail_from        IN     hig_alert_type_mail.hatm_mail_from%TYPE
                       ,pi_params           IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                       ,pi_params_derived   IN     nm3type.tab_varchar1 DEFAULT CAST(NULL AS nm3type.tab_varchar1)
                       ,pi_trigger_name     IN     hig_alert_types.halt_trigger_name%TYPE
                       ,po_trigger_dropped     OUT varchar2
                       ,po_message_severity    OUT hig_codes.hco_code%TYPE
                       ,po_message_cursor      OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT create_mail_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Mail Subject'
                               ,pi_parameter_value => pi_mail_subject);
    --
    IF NVL(pi_mail_type, 'N') NOT IN ('H','T') THEN
        --
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 30
                     ,pi_supplementary_info => 'Mail Type must be either H (HTML) or T (Plain Text)');
        --
    END IF;
    --
    --check the params tables have matching row counts
    IF pi_params.COUNT != pi_params_derived.COUNT
     THEN
        --The attribute tables passed in must have matching row counts
        hig.raise_ner(pi_appl               => 'AWLRS'
                     ,pi_id                 => 5
                     ,pi_supplementary_info => 'awlrs_alerts_api.create_mail');
    END IF;
    /*
    ||insert into hig_alert_type_mail.
    */
    INSERT
      INTO hig_alert_type_mail
          (hatm_id
          ,hatm_halt_id
          ,hatm_subject
          ,hatm_mail_text
          ,hatm_mail_type
          ,hatm_mail_from
          ,hatm_param_1
          ,hatm_p1_derived
          ,hatm_param_2
          ,hatm_p2_derived
          ,hatm_param_3
          ,hatm_p3_derived
          ,hatm_param_4
          ,hatm_p4_derived
          ,hatm_param_5
          ,hatm_p5_derived
          ,hatm_param_6
          ,hatm_p6_derived
          ,hatm_param_7
          ,hatm_p7_derived
          ,hatm_param_8
          ,hatm_p8_derived
          ,hatm_param_9
          ,hatm_p9_derived
          ,hatm_param_10
          ,hatm_p10_derived
          ,hatm_param_11
          ,hatm_p11_derived
          ,hatm_param_12
          ,hatm_p12_derived
          ,hatm_param_13
          ,hatm_p13_derived
          ,hatm_param_14
          ,hatm_p14_derived
          ,hatm_param_15
          ,hatm_p15_derived
          ,hatm_param_16
          ,hatm_p16_derived
          ,hatm_param_17
          ,hatm_p17_derived
          ,hatm_param_18
          ,hatm_p18_derived
          ,hatm_param_19
          ,hatm_p19_derived
          ,hatm_param_20
          ,hatm_p20_derived
          )
    VALUES (hatm_id_seq.NEXTVAL
           ,pi_alert_id
           ,pi_mail_subject
           ,pi_mail_text 
           ,pi_mail_type
           ,pi_mail_from
           ,pi_params(1)
           ,pi_params_derived(1)
           ,pi_params(2)
           ,pi_params_derived(2)
           ,pi_params(3)
           ,pi_params_derived(3)
           ,pi_params(4)
           ,pi_params_derived(4)
           ,pi_params(5)
           ,pi_params_derived(5)
           ,pi_params(6)
           ,pi_params_derived(6)
           ,pi_params(7)
           ,pi_params_derived(7)
           ,pi_params(8)
           ,pi_params_derived(8)
           ,pi_params(9)
           ,pi_params_derived(9)
           ,pi_params(10)
           ,pi_params_derived(10)
           ,pi_params(11)
           ,pi_params_derived(11)
           ,pi_params(12)
           ,pi_params_derived(12)
           ,pi_params(13)
           ,pi_params_derived(13)
           ,pi_params(14)
           ,pi_params_derived(14)
           ,pi_params(15)
           ,pi_params_derived(15)
           ,pi_params(16)
           ,pi_params_derived(16)
           ,pi_params(17)
           ,pi_params_derived(17)
           ,pi_params(18)
           ,pi_params_derived(18)
           ,pi_params(19)
           ,pi_params_derived(19)
           ,pi_params(20)
           ,pi_params_derived(20)
           );
    --
   --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_mail_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_mail;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_mail(pi_old_mail_id           IN     hig_alert_type_mail.hatm_id%TYPE
                       ,pi_old_alert_id          IN     hig_alert_type_mail.hatm_halt_id%TYPE
                       ,pi_old_mail_from         IN     hig_alert_type_mail.hatm_mail_from%TYPE
                       ,pi_old_mail_subject      IN     hig_alert_type_mail.hatm_subject%TYPE
                       ,pi_old_mail_text         IN     hig_alert_type_mail.hatm_mail_text%TYPE
                       ,pi_old_mail_type         IN     hig_alert_type_mail.hatm_mail_type%TYPE
                       ,pi_old_param_1           IN     hig_alert_type_mail.hatm_param_1%TYPE
                       ,pi_old_param_1_derived   IN     hig_alert_type_mail.hatm_p1_derived%TYPE
                       ,pi_old_param_2           IN     hig_alert_type_mail.hatm_param_2%TYPE
                       ,pi_old_param_2_derived   IN     hig_alert_type_mail.hatm_p2_derived%TYPE
                       ,pi_old_param_3           IN     hig_alert_type_mail.hatm_param_3%TYPE
                       ,pi_old_param_3_derived   IN     hig_alert_type_mail.hatm_p3_derived%TYPE
                       ,pi_old_param_4           IN     hig_alert_type_mail.hatm_param_4%TYPE
                       ,pi_old_param_4_derived   IN     hig_alert_type_mail.hatm_p4_derived%TYPE
                       ,pi_old_param_5           IN     hig_alert_type_mail.hatm_param_5%TYPE
                       ,pi_old_param_5_derived   IN     hig_alert_type_mail.hatm_p5_derived%TYPE
                       ,pi_old_param_6           IN     hig_alert_type_mail.hatm_param_6%TYPE
                       ,pi_old_param_6_derived   IN     hig_alert_type_mail.hatm_p6_derived%TYPE
                       ,pi_old_param_7           IN     hig_alert_type_mail.hatm_param_7%TYPE
                       ,pi_old_param_7_derived   IN     hig_alert_type_mail.hatm_p7_derived%TYPE
                       ,pi_old_param_8           IN     hig_alert_type_mail.hatm_param_8%TYPE
                       ,pi_old_param_8_derived   IN     hig_alert_type_mail.hatm_p8_derived%TYPE
                       ,pi_old_param_9           IN     hig_alert_type_mail.hatm_param_9%TYPE
                       ,pi_old_param_9_derived   IN     hig_alert_type_mail.hatm_p9_derived%TYPE
                       ,pi_old_param_10          IN     hig_alert_type_mail.hatm_param_10%TYPE
                       ,pi_old_param_10_derived  IN     hig_alert_type_mail.hatm_p10_derived%TYPE
                       ,pi_old_param_11          IN     hig_alert_type_mail.hatm_param_11%TYPE
                       ,pi_old_param_11_derived  IN     hig_alert_type_mail.hatm_p11_derived%TYPE
                       ,pi_old_param_12          IN     hig_alert_type_mail.hatm_param_12%TYPE
                       ,pi_old_param_12_derived  IN     hig_alert_type_mail.hatm_p12_derived%TYPE
                       ,pi_old_param_13          IN     hig_alert_type_mail.hatm_param_13%TYPE
                       ,pi_old_param_13_derived  IN     hig_alert_type_mail.hatm_p13_derived%TYPE
                       ,pi_old_param_14          IN     hig_alert_type_mail.hatm_param_14%TYPE
                       ,pi_old_param_14_derived  IN     hig_alert_type_mail.hatm_p14_derived%TYPE
                       ,pi_old_param_15          IN     hig_alert_type_mail.hatm_param_15%TYPE
                       ,pi_old_param_15_derived  IN     hig_alert_type_mail.hatm_p15_derived%TYPE
                       ,pi_old_param_16          IN     hig_alert_type_mail.hatm_param_16%TYPE
                       ,pi_old_param_16_derived  IN     hig_alert_type_mail.hatm_p16_derived%TYPE
                       ,pi_old_param_17          IN     hig_alert_type_mail.hatm_param_17%TYPE
                       ,pi_old_param_17_derived  IN     hig_alert_type_mail.hatm_p17_derived%TYPE
                       ,pi_old_param_18          IN     hig_alert_type_mail.hatm_param_18%TYPE
                       ,pi_old_param_18_derived  IN     hig_alert_type_mail.hatm_p18_derived%TYPE
                       ,pi_old_param_19          IN     hig_alert_type_mail.hatm_param_19%TYPE
                       ,pi_old_param_19_derived  IN     hig_alert_type_mail.hatm_p19_derived%TYPE
                       ,pi_old_param_20          IN     hig_alert_type_mail.hatm_param_20%TYPE
                       ,pi_old_param_20_derived  IN     hig_alert_type_mail.hatm_p20_derived%TYPE
                       ,pi_new_mail_id           IN     hig_alert_type_mail.hatm_id%TYPE
                       ,pi_new_alert_id          IN     hig_alert_type_mail.hatm_halt_id%TYPE
                       ,pi_new_mail_from         IN     hig_alert_type_mail.hatm_mail_from%TYPE
                       ,pi_new_mail_subject      IN     hig_alert_type_mail.hatm_subject%TYPE
                       ,pi_new_mail_text         IN     hig_alert_type_mail.hatm_mail_text%TYPE
                       ,pi_new_mail_type         IN     hig_alert_type_mail.hatm_mail_type%TYPE
                       ,pi_new_param_1           IN     hig_alert_type_mail.hatm_param_1%TYPE
                       ,pi_new_param_1_derived   IN     hig_alert_type_mail.hatm_p1_derived%TYPE
                       ,pi_new_param_2           IN     hig_alert_type_mail.hatm_param_2%TYPE
                       ,pi_new_param_2_derived   IN     hig_alert_type_mail.hatm_p2_derived%TYPE
                       ,pi_new_param_3           IN     hig_alert_type_mail.hatm_param_3%TYPE
                       ,pi_new_param_3_derived   IN     hig_alert_type_mail.hatm_p3_derived%TYPE
                       ,pi_new_param_4           IN     hig_alert_type_mail.hatm_param_4%TYPE
                       ,pi_new_param_4_derived   IN     hig_alert_type_mail.hatm_p4_derived%TYPE
                       ,pi_new_param_5           IN     hig_alert_type_mail.hatm_param_5%TYPE
                       ,pi_new_param_5_derived   IN     hig_alert_type_mail.hatm_p5_derived%TYPE
                       ,pi_new_param_6           IN     hig_alert_type_mail.hatm_param_6%TYPE
                       ,pi_new_param_6_derived   IN     hig_alert_type_mail.hatm_p6_derived%TYPE
                       ,pi_new_param_7           IN     hig_alert_type_mail.hatm_param_7%TYPE
                       ,pi_new_param_7_derived   IN     hig_alert_type_mail.hatm_p7_derived%TYPE
                       ,pi_new_param_8           IN     hig_alert_type_mail.hatm_param_8%TYPE
                       ,pi_new_param_8_derived   IN     hig_alert_type_mail.hatm_p8_derived%TYPE
                       ,pi_new_param_9           IN     hig_alert_type_mail.hatm_param_9%TYPE
                       ,pi_new_param_9_derived   IN     hig_alert_type_mail.hatm_p9_derived%TYPE
                       ,pi_new_param_10          IN     hig_alert_type_mail.hatm_param_10%TYPE
                       ,pi_new_param_10_derived  IN     hig_alert_type_mail.hatm_p10_derived%TYPE
                       ,pi_new_param_11          IN     hig_alert_type_mail.hatm_param_11%TYPE
                       ,pi_new_param_11_derived  IN     hig_alert_type_mail.hatm_p11_derived%TYPE
                       ,pi_new_param_12          IN     hig_alert_type_mail.hatm_param_12%TYPE
                       ,pi_new_param_12_derived  IN     hig_alert_type_mail.hatm_p12_derived%TYPE
                       ,pi_new_param_13          IN     hig_alert_type_mail.hatm_param_13%TYPE
                       ,pi_new_param_13_derived  IN     hig_alert_type_mail.hatm_p13_derived%TYPE
                       ,pi_new_param_14          IN     hig_alert_type_mail.hatm_param_14%TYPE
                       ,pi_new_param_14_derived  IN     hig_alert_type_mail.hatm_p14_derived%TYPE
                       ,pi_new_param_15          IN     hig_alert_type_mail.hatm_param_15%TYPE
                       ,pi_new_param_15_derived  IN     hig_alert_type_mail.hatm_p15_derived%TYPE
                       ,pi_new_param_16          IN     hig_alert_type_mail.hatm_param_16%TYPE
                       ,pi_new_param_16_derived  IN     hig_alert_type_mail.hatm_p16_derived%TYPE
                       ,pi_new_param_17          IN     hig_alert_type_mail.hatm_param_17%TYPE
                       ,pi_new_param_17_derived  IN     hig_alert_type_mail.hatm_p17_derived%TYPE
                       ,pi_new_param_18          IN     hig_alert_type_mail.hatm_param_18%TYPE
                       ,pi_new_param_18_derived  IN     hig_alert_type_mail.hatm_p18_derived%TYPE
                       ,pi_new_param_19          IN     hig_alert_type_mail.hatm_param_19%TYPE
                       ,pi_new_param_19_derived  IN     hig_alert_type_mail.hatm_p19_derived%TYPE
                       ,pi_new_param_20          IN     hig_alert_type_mail.hatm_param_20%TYPE
                       ,pi_new_param_20_derived  IN     hig_alert_type_mail.hatm_p20_derived%TYPE
                       ,pi_trigger_name          IN     hig_alert_types.halt_trigger_name%TYPE
                       ,po_trigger_dropped          OUT varchar2
                       ,po_message_severity         OUT hig_codes.hco_code%TYPE
                       ,po_message_cursor           OUT sys_refcursor)
  IS
    --
    lr_db_rec        hig_alert_type_mail%ROWTYPE;
    lv_upd           varchar2(1) := 'N';
    lv_error_text    varchar2(32767);
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_alert_type_mail
       WHERE hatm_id = pi_old_mail_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Mail Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_mail_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Mail Id'
                               ,pi_parameter_value => pi_new_mail_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_new_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Mail Subject'
                               ,pi_parameter_value => pi_new_mail_subject);
    --
    IF NVL(pi_new_mail_type, 'N') NOT IN ('H','T') THEN
        --
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 30
                     ,pi_supplementary_info => 'Mail Type must be either H (HTML) or T (Plain Text)');
        --
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.hatm_id != pi_old_mail_id
     OR (lr_db_rec.hatm_id IS NULL AND pi_old_mail_id IS NOT NULL)
     OR (lr_db_rec.hatm_id IS NOT NULL AND pi_old_mail_id IS NULL)
     --
     OR (lr_db_rec.hatm_halt_id != pi_old_alert_id)
     OR (lr_db_rec.hatm_halt_id IS NULL AND pi_old_alert_id IS NOT NULL)
     OR (lr_db_rec.hatm_halt_id IS NOT NULL AND pi_old_alert_id IS NULL)
     --
     OR (UPPER(lr_db_rec.hatm_subject) != UPPER(pi_old_mail_subject))
     OR (UPPER(lr_db_rec.hatm_subject) IS NULL AND UPPER(pi_old_mail_subject) IS NOT NULL)
     OR (UPPER(lr_db_rec.hatm_subject) IS NOT NULL AND UPPER(pi_old_mail_subject) IS NULL)
     --
     OR (UPPER(lr_db_rec.hatm_mail_text) != UPPER(pi_old_mail_text))
     OR (UPPER(lr_db_rec.hatm_mail_text) IS NULL AND UPPER(pi_old_mail_text) IS NOT NULL)
     OR (UPPER(lr_db_rec.hatm_mail_text) IS NOT NULL AND UPPER(pi_old_mail_text) IS NULL)
     --
     OR (lr_db_rec.hatm_mail_type != pi_old_mail_type)
     OR (lr_db_rec.hatm_mail_type IS NULL AND pi_old_mail_type IS NOT NULL)
     OR (lr_db_rec.hatm_mail_type IS NOT NULL AND pi_old_mail_type IS NULL)
     --
     OR (UPPER(lr_db_rec.hatm_mail_from) != UPPER(pi_old_mail_from))
     OR (UPPER(lr_db_rec.hatm_mail_from) IS NULL AND UPPER(pi_old_mail_from) IS NOT NULL)
     OR (UPPER(lr_db_rec.hatm_mail_from) IS NOT NULL AND UPPER(pi_old_mail_from) IS NULL)
     --
     OR (lr_db_rec.hatm_param_1 != pi_old_param_1)
     OR (lr_db_rec.hatm_param_1 IS NULL AND pi_old_param_1 IS NOT NULL)
     OR (lr_db_rec.hatm_param_1 IS NOT NULL AND pi_old_param_1 IS NULL)
     --
     OR (lr_db_rec.hatm_p1_derived != pi_old_param_1_derived)
     OR (lr_db_rec.hatm_p1_derived IS NULL AND pi_old_param_1_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p1_derived IS NOT NULL AND pi_old_param_1_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_2 != pi_old_param_2)
     OR (lr_db_rec.hatm_param_2 IS NULL AND pi_old_param_2 IS NOT NULL)
     OR (lr_db_rec.hatm_param_2 IS NOT NULL AND pi_old_param_2 IS NULL)
     --
     OR (lr_db_rec.hatm_p2_derived != pi_old_param_2_derived)
     OR (lr_db_rec.hatm_p2_derived IS NULL AND pi_old_param_2_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p2_derived IS NOT NULL AND pi_old_param_2_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_3 != pi_old_param_3)
     OR (lr_db_rec.hatm_param_3 IS NULL AND pi_old_param_3 IS NOT NULL)
     OR (lr_db_rec.hatm_param_3 IS NOT NULL AND pi_old_param_3 IS NULL)
     --
     OR (lr_db_rec.hatm_p3_derived != pi_old_param_3_derived)
     OR (lr_db_rec.hatm_p3_derived IS NULL AND pi_old_param_3_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p3_derived IS NOT NULL AND pi_old_param_3_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_4 != pi_old_param_4)
     OR (lr_db_rec.hatm_param_4 IS NULL AND pi_old_param_4 IS NOT NULL)
     OR (lr_db_rec.hatm_param_4 IS NOT NULL AND pi_old_param_4 IS NULL)
     --
     OR (lr_db_rec.hatm_p4_derived != pi_old_param_4_derived)
     OR (lr_db_rec.hatm_p4_derived IS NULL AND pi_old_param_4_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p4_derived IS NOT NULL AND pi_old_param_4_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_5 != pi_old_param_5)
     OR (lr_db_rec.hatm_param_5 IS NULL AND pi_old_param_5 IS NOT NULL)
     OR (lr_db_rec.hatm_param_5 IS NOT NULL AND pi_old_param_5 IS NULL)
     --
     OR (lr_db_rec.hatm_p5_derived != pi_old_param_5_derived)
     OR (lr_db_rec.hatm_p5_derived IS NULL AND pi_old_param_5_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p5_derived IS NOT NULL AND pi_old_param_5_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_6 != pi_old_param_6)
     OR (lr_db_rec.hatm_param_6 IS NULL AND pi_old_param_6 IS NOT NULL)
     OR (lr_db_rec.hatm_param_6 IS NOT NULL AND pi_old_param_6 IS NULL)
     --
     OR (lr_db_rec.hatm_p6_derived != pi_old_param_6_derived)
     OR (lr_db_rec.hatm_p6_derived IS NULL AND pi_old_param_6_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p6_derived IS NOT NULL AND pi_old_param_6_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_7 != pi_old_param_7)
     OR (lr_db_rec.hatm_param_7 IS NULL AND pi_old_param_7 IS NOT NULL)
     OR (lr_db_rec.hatm_param_7 IS NOT NULL AND pi_old_param_7 IS NULL)
     --
     OR (lr_db_rec.hatm_p7_derived != pi_old_param_7_derived)
     OR (lr_db_rec.hatm_p7_derived IS NULL AND pi_old_param_7_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p7_derived IS NOT NULL AND pi_old_param_7_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_8 != pi_old_param_8)
     OR (lr_db_rec.hatm_param_8 IS NULL AND pi_old_param_8 IS NOT NULL)
     OR (lr_db_rec.hatm_param_8 IS NOT NULL AND pi_old_param_8 IS NULL)
     --
     OR (lr_db_rec.hatm_p8_derived != pi_old_param_8_derived)
     OR (lr_db_rec.hatm_p8_derived IS NULL AND pi_old_param_8_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p8_derived IS NOT NULL AND pi_old_param_8_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_9 != pi_old_param_9)
     OR (lr_db_rec.hatm_param_9 IS NULL AND pi_old_param_9 IS NOT NULL)
     OR (lr_db_rec.hatm_param_9 IS NOT NULL AND pi_old_param_9 IS NULL)
     --
     OR (lr_db_rec.hatm_p9_derived != pi_old_param_9_derived)
     OR (lr_db_rec.hatm_p9_derived IS NULL AND pi_old_param_9_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p9_derived IS NOT NULL AND pi_old_param_9_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_10 != pi_old_param_10)
     OR (lr_db_rec.hatm_param_10 IS NULL AND pi_old_param_10 IS NOT NULL)
     OR (lr_db_rec.hatm_param_10 IS NOT NULL AND pi_old_param_10 IS NULL)
     --
     OR (lr_db_rec.hatm_p10_derived != pi_old_param_10_derived)
     OR (lr_db_rec.hatm_p10_derived IS NULL AND pi_old_param_10_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p10_derived IS NOT NULL AND pi_old_param_10_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_11 != pi_old_param_11)
     OR (lr_db_rec.hatm_param_11 IS NULL AND pi_old_param_11 IS NOT NULL)
     OR (lr_db_rec.hatm_param_11 IS NOT NULL AND pi_old_param_11 IS NULL)
     --
     OR (lr_db_rec.hatm_p11_derived != pi_old_param_11_derived)
     OR (lr_db_rec.hatm_p11_derived IS NULL AND pi_old_param_11_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p11_derived IS NOT NULL AND pi_old_param_11_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_12 != pi_old_param_12)
     OR (lr_db_rec.hatm_param_12 IS NULL AND pi_old_param_12 IS NOT NULL)
     OR (lr_db_rec.hatm_param_12 IS NOT NULL AND pi_old_param_12 IS NULL)
     --
     OR (lr_db_rec.hatm_p12_derived != pi_old_param_12_derived)
     OR (lr_db_rec.hatm_p12_derived IS NULL AND pi_old_param_12_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p12_derived IS NOT NULL AND pi_old_param_12_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_13 != pi_old_param_13)
     OR (lr_db_rec.hatm_param_13 IS NULL AND pi_old_param_13 IS NOT NULL)
     OR (lr_db_rec.hatm_param_13 IS NOT NULL AND pi_old_param_13 IS NULL)
     --
     OR (lr_db_rec.hatm_p13_derived != pi_old_param_13_derived)
     OR (lr_db_rec.hatm_p13_derived IS NULL AND pi_old_param_13_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p13_derived IS NOT NULL AND pi_old_param_13_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_14 != pi_old_param_14)
     OR (lr_db_rec.hatm_param_14 IS NULL AND pi_old_param_14 IS NOT NULL)
     OR (lr_db_rec.hatm_param_14 IS NOT NULL AND pi_old_param_14 IS NULL)
     --
     OR (lr_db_rec.hatm_p14_derived != pi_old_param_14_derived)
     OR (lr_db_rec.hatm_p14_derived IS NULL AND pi_old_param_14_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p14_derived IS NOT NULL AND pi_old_param_14_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_15 != pi_old_param_15)
     OR (lr_db_rec.hatm_param_15 IS NULL AND pi_old_param_15 IS NOT NULL)
     OR (lr_db_rec.hatm_param_15 IS NOT NULL AND pi_old_param_15 IS NULL)
     --
     OR (lr_db_rec.hatm_p15_derived != pi_old_param_15_derived)
     OR (lr_db_rec.hatm_p15_derived IS NULL AND pi_old_param_15_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p15_derived IS NOT NULL AND pi_old_param_15_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_16 != pi_old_param_16)
     OR (lr_db_rec.hatm_param_16 IS NULL AND pi_old_param_16 IS NOT NULL)
     OR (lr_db_rec.hatm_param_16 IS NOT NULL AND pi_old_param_16 IS NULL)
     --
     OR (lr_db_rec.hatm_p16_derived != pi_old_param_16_derived)
     OR (lr_db_rec.hatm_p16_derived IS NULL AND pi_old_param_16_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p16_derived IS NOT NULL AND pi_old_param_16_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_17 != pi_old_param_17)
     OR (lr_db_rec.hatm_param_17 IS NULL AND pi_old_param_17 IS NOT NULL)
     OR (lr_db_rec.hatm_param_17 IS NOT NULL AND pi_old_param_17 IS NULL)
     --
     OR (lr_db_rec.hatm_p17_derived != pi_old_param_17_derived)
     OR (lr_db_rec.hatm_p17_derived IS NULL AND pi_old_param_17_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p17_derived IS NOT NULL AND pi_old_param_17_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_18 != pi_old_param_18)
     OR (lr_db_rec.hatm_param_18 IS NULL AND pi_old_param_18 IS NOT NULL)
     OR (lr_db_rec.hatm_param_18 IS NOT NULL AND pi_old_param_18 IS NULL)
     --
     OR (lr_db_rec.hatm_p18_derived != pi_old_param_18_derived)
     OR (lr_db_rec.hatm_p18_derived IS NULL AND pi_old_param_18_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p18_derived IS NOT NULL AND pi_old_param_18_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_19 != pi_old_param_19)
     OR (lr_db_rec.hatm_param_19 IS NULL AND pi_old_param_19 IS NOT NULL)
     OR (lr_db_rec.hatm_param_19 IS NOT NULL AND pi_old_param_19 IS NULL)
     --
     OR (lr_db_rec.hatm_p19_derived != pi_old_param_19_derived)
     OR (lr_db_rec.hatm_p19_derived IS NULL AND pi_old_param_19_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p19_derived IS NOT NULL AND pi_old_param_19_derived IS NULL)
     --
     OR (lr_db_rec.hatm_param_20 != pi_old_param_20)
     OR (lr_db_rec.hatm_param_20 IS NULL AND pi_old_param_20 IS NOT NULL)
     OR (lr_db_rec.hatm_param_20 IS NOT NULL AND pi_old_param_20 IS NULL)
     --
     OR (lr_db_rec.hatm_p20_derived != pi_old_param_20_derived)
     OR (lr_db_rec.hatm_p20_derived IS NULL AND pi_old_param_20_derived IS NOT NULL)
     OR (lr_db_rec.hatm_p20_derived IS NOT NULL AND pi_old_param_20_derived IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      --TODO review all update apis, no need to check for this
      IF pi_old_mail_id != pi_new_mail_id
       OR (pi_old_mail_id IS NULL AND pi_new_mail_id IS NOT NULL)
       OR (pi_old_mail_id IS NOT NULL AND pi_new_mail_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_alert_id != pi_new_alert_id
       OR (pi_old_alert_id IS NULL AND pi_new_alert_id IS NOT NULL)
       OR (pi_old_alert_id IS NOT NULL AND pi_new_alert_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_mail_subject) != UPPER(pi_new_mail_subject)
       OR (UPPER(pi_old_mail_subject) IS NULL AND UPPER(pi_new_mail_subject) IS NOT NULL)
       OR (UPPER(pi_old_mail_subject) IS NOT NULL AND UPPER(pi_new_mail_subject) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_mail_text) != UPPER(pi_new_mail_text)
       OR (UPPER(pi_old_mail_text) IS NULL AND UPPER(pi_new_mail_text) IS NOT NULL)
       OR (UPPER(pi_old_mail_text) IS NOT NULL AND UPPER(pi_new_mail_text) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_mail_type != pi_new_mail_type
       OR (pi_old_mail_type IS NULL AND pi_new_mail_type IS NOT NULL)
       OR (pi_old_mail_type IS NOT NULL AND pi_new_mail_type IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_mail_from) != UPPER(pi_new_mail_from)
       OR (UPPER(pi_old_mail_from) IS NULL AND UPPER(pi_new_mail_from) IS NOT NULL)
       OR (UPPER(pi_old_mail_from) IS NOT NULL AND UPPER(pi_new_mail_from) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_1 != pi_new_param_1
       OR (pi_old_param_1 IS NULL AND pi_new_param_1 IS NOT NULL)
       OR (pi_old_param_1 IS NOT NULL AND pi_new_param_1 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_1_derived != pi_new_param_1_derived
       OR (pi_old_param_1_derived IS NULL AND pi_new_param_1_derived IS NOT NULL)
       OR (pi_old_param_1_derived IS NOT NULL AND pi_new_param_1_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_2 != pi_new_param_2
       OR (pi_old_param_2 IS NULL AND pi_new_param_2 IS NOT NULL)
       OR (pi_old_param_2 IS NOT NULL AND pi_new_param_2 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_2_derived != pi_new_param_2_derived
       OR (pi_old_param_2_derived IS NULL AND pi_new_param_2_derived IS NOT NULL)
       OR (pi_old_param_2_derived IS NOT NULL AND pi_new_param_2_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_3 != pi_new_param_3
       OR (pi_old_param_3 IS NULL AND pi_new_param_3 IS NOT NULL)
       OR (pi_old_param_3 IS NOT NULL AND pi_new_param_3 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_3_derived != pi_new_param_3_derived
       OR (pi_old_param_3_derived IS NULL AND pi_new_param_3_derived IS NOT NULL)
       OR (pi_old_param_3_derived IS NOT NULL AND pi_new_param_3_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_4 != pi_new_param_4
       OR (pi_old_param_4 IS NULL AND pi_new_param_4 IS NOT NULL)
       OR (pi_old_param_4 IS NOT NULL AND pi_new_param_4 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_4_derived != pi_new_param_4_derived
       OR (pi_old_param_4_derived IS NULL AND pi_new_param_4_derived IS NOT NULL)
       OR (pi_old_param_4_derived IS NOT NULL AND pi_new_param_4_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_5 != pi_new_param_5
       OR (pi_old_param_5 IS NULL AND pi_new_param_5 IS NOT NULL)
       OR (pi_old_param_5 IS NOT NULL AND pi_new_param_5 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_5_derived != pi_new_param_5_derived
       OR (pi_old_param_5_derived IS NULL AND pi_new_param_5_derived IS NOT NULL)
       OR (pi_old_param_5_derived IS NOT NULL AND pi_new_param_5_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_6 != pi_new_param_6
       OR (pi_old_param_6 IS NULL AND pi_new_param_6 IS NOT NULL)
       OR (pi_old_param_6 IS NOT NULL AND pi_new_param_6 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_6_derived != pi_new_param_6_derived
       OR (pi_old_param_6_derived IS NULL AND pi_new_param_6_derived IS NOT NULL)
       OR (pi_old_param_6_derived IS NOT NULL AND pi_new_param_6_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_7 != pi_new_param_7
       OR (pi_old_param_7 IS NULL AND pi_new_param_7 IS NOT NULL)
       OR (pi_old_param_7 IS NOT NULL AND pi_new_param_7 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_7_derived != pi_new_param_7_derived
       OR (pi_old_param_7_derived IS NULL AND pi_new_param_7_derived IS NOT NULL)
       OR (pi_old_param_7_derived IS NOT NULL AND pi_new_param_7_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_8 != pi_new_param_8
       OR (pi_old_param_8 IS NULL AND pi_new_param_8 IS NOT NULL)
       OR (pi_old_param_8 IS NOT NULL AND pi_new_param_8 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_8_derived != pi_new_param_8_derived
       OR (pi_old_param_8_derived IS NULL AND pi_new_param_8_derived IS NOT NULL)
       OR (pi_old_param_8_derived IS NOT NULL AND pi_new_param_8_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_9 != pi_new_param_9
       OR (pi_old_param_9 IS NULL AND pi_new_param_9 IS NOT NULL)
       OR (pi_old_param_9 IS NOT NULL AND pi_new_param_9 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_9_derived != pi_new_param_9_derived
       OR (pi_old_param_9_derived IS NULL AND pi_new_param_9_derived IS NOT NULL)
       OR (pi_old_param_9_derived IS NOT NULL AND pi_new_param_9_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_10 != pi_new_param_10
       OR (pi_old_param_10 IS NULL AND pi_new_param_10 IS NOT NULL)
       OR (pi_old_param_10 IS NOT NULL AND pi_new_param_10 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_10_derived != pi_new_param_10_derived
       OR (pi_old_param_10_derived IS NULL AND pi_new_param_10_derived IS NOT NULL)
       OR (pi_old_param_10_derived IS NOT NULL AND pi_new_param_10_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_11 != pi_new_param_11
       OR (pi_old_param_11 IS NULL AND pi_new_param_11 IS NOT NULL)
       OR (pi_old_param_11 IS NOT NULL AND pi_new_param_11 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_11_derived != pi_new_param_11_derived
       OR (pi_old_param_11_derived IS NULL AND pi_new_param_11_derived IS NOT NULL)
       OR (pi_old_param_11_derived IS NOT NULL AND pi_new_param_11_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_12 != pi_new_param_12
       OR (pi_old_param_12 IS NULL AND pi_new_param_12 IS NOT NULL)
       OR (pi_old_param_12 IS NOT NULL AND pi_new_param_12 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_12_derived != pi_new_param_12_derived
       OR (pi_old_param_12_derived IS NULL AND pi_new_param_12_derived IS NOT NULL)
       OR (pi_old_param_12_derived IS NOT NULL AND pi_new_param_12_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_13 != pi_new_param_13
       OR (pi_old_param_13 IS NULL AND pi_new_param_13 IS NOT NULL)
       OR (pi_old_param_13 IS NOT NULL AND pi_new_param_13 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_13_derived != pi_new_param_13_derived
       OR (pi_old_param_13_derived IS NULL AND pi_new_param_13_derived IS NOT NULL)
       OR (pi_old_param_13_derived IS NOT NULL AND pi_new_param_13_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_14 != pi_new_param_14
       OR (pi_old_param_14 IS NULL AND pi_new_param_14 IS NOT NULL)
       OR (pi_old_param_14 IS NOT NULL AND pi_new_param_14 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_14_derived != pi_new_param_14_derived
       OR (pi_old_param_14_derived IS NULL AND pi_new_param_14_derived IS NOT NULL)
       OR (pi_old_param_14_derived IS NOT NULL AND pi_new_param_14_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_15 != pi_new_param_15
       OR (pi_old_param_15 IS NULL AND pi_new_param_15 IS NOT NULL)
       OR (pi_old_param_15 IS NOT NULL AND pi_new_param_15 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_15_derived != pi_new_param_15_derived
       OR (pi_old_param_15_derived IS NULL AND pi_new_param_15_derived IS NOT NULL)
       OR (pi_old_param_15_derived IS NOT NULL AND pi_new_param_15_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_16 != pi_new_param_16
       OR (pi_old_param_16 IS NULL AND pi_new_param_16 IS NOT NULL)
       OR (pi_old_param_16 IS NOT NULL AND pi_new_param_16 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_16_derived != pi_new_param_16_derived
       OR (pi_old_param_16_derived IS NULL AND pi_new_param_16_derived IS NOT NULL)
       OR (pi_old_param_16_derived IS NOT NULL AND pi_new_param_16_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_17 != pi_new_param_17
       OR (pi_old_param_17 IS NULL AND pi_new_param_17 IS NOT NULL)
       OR (pi_old_param_17 IS NOT NULL AND pi_new_param_17 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_17_derived != pi_new_param_17_derived
       OR (pi_old_param_17_derived IS NULL AND pi_new_param_17_derived IS NOT NULL)
       OR (pi_old_param_17_derived IS NOT NULL AND pi_new_param_17_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_18 != pi_new_param_18
       OR (pi_old_param_18 IS NULL AND pi_new_param_18 IS NOT NULL)
       OR (pi_old_param_18 IS NOT NULL AND pi_new_param_18 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_18_derived != pi_new_param_18_derived
       OR (pi_old_param_18_derived IS NULL AND pi_new_param_18_derived IS NOT NULL)
       OR (pi_old_param_18_derived IS NOT NULL AND pi_new_param_18_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_19 != pi_new_param_19
       OR (pi_old_param_19 IS NULL AND pi_new_param_19 IS NOT NULL)
       OR (pi_old_param_19 IS NOT NULL AND pi_new_param_19 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_19_derived != pi_new_param_19_derived
       OR (pi_old_param_19_derived IS NULL AND pi_new_param_19_derived IS NOT NULL)
       OR (pi_old_param_19_derived IS NOT NULL AND pi_new_param_19_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_20 != pi_new_param_20
       OR (pi_old_param_20 IS NULL AND pi_new_param_20 IS NOT NULL)
       OR (pi_old_param_20 IS NOT NULL AND pi_new_param_20 IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_param_20_derived != pi_new_param_20_derived
       OR (pi_old_param_20_derived IS NULL AND pi_new_param_20_derived IS NOT NULL)
       OR (pi_old_param_20_derived IS NOT NULL AND pi_new_param_20_derived IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --      
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_alert_type_mail
           SET hatm_subject     = pi_new_mail_subject
              ,hatm_mail_text   = pi_new_mail_text
              ,hatm_mail_type   = pi_new_mail_type
              ,hatm_mail_from   = pi_new_mail_from
              ,hatm_param_1     = pi_new_param_1
              ,hatm_p1_derived  = pi_new_param_1_derived
              ,hatm_param_2     = pi_new_param_2
              ,hatm_p2_derived  = pi_new_param_2_derived
              ,hatm_param_3     = pi_new_param_3
              ,hatm_p3_derived  = pi_new_param_3_derived
              ,hatm_param_4     = pi_new_param_4
              ,hatm_p4_derived  = pi_new_param_4_derived
              ,hatm_param_5     = pi_new_param_5
              ,hatm_p5_derived  = pi_new_param_5_derived
              ,hatm_param_6     = pi_new_param_6
              ,hatm_p6_derived  = pi_new_param_6_derived
              ,hatm_param_7     = pi_new_param_7
              ,hatm_p7_derived  = pi_new_param_7_derived
              ,hatm_param_8     = pi_new_param_8
              ,hatm_p8_derived  = pi_new_param_8_derived
              ,hatm_param_9     = pi_new_param_9
              ,hatm_p9_derived  = pi_new_param_9_derived
              ,hatm_param_10    = pi_new_param_10
              ,hatm_p10_derived = pi_new_param_10_derived
              ,hatm_param_11    = pi_new_param_11
              ,hatm_p11_derived = pi_new_param_11_derived
              ,hatm_param_12    = pi_new_param_12
              ,hatm_p12_derived = pi_new_param_12_derived
              ,hatm_param_13    = pi_new_param_13
              ,hatm_p13_derived = pi_new_param_13_derived
              ,hatm_param_14    = pi_new_param_14
              ,hatm_p14_derived = pi_new_param_14_derived
              ,hatm_param_15    = pi_new_param_15
              ,hatm_p15_derived = pi_new_param_15_derived
              ,hatm_param_16    = pi_new_param_16
              ,hatm_p16_derived = pi_new_param_16_derived
              ,hatm_param_17    = pi_new_param_17
              ,hatm_p17_derived = pi_new_param_17_derived
              ,hatm_param_18    = pi_new_param_18
              ,hatm_p18_derived = pi_new_param_18_derived
              ,hatm_param_19    = pi_new_param_19
              ,hatm_p19_derived = pi_new_param_19_derived
              ,hatm_param_20    = pi_new_param_20
              ,hatm_p20_derived = pi_new_param_20_derived
         WHERE hatm_id          = pi_old_mail_id;          
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF; 
    END IF;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_old_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_mail_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_mail;
                          
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION mail_exists(pi_hatm_id    IN     hig_alert_type_mail.hatm_id%TYPE)
  
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM hig_alert_type_mail
     WHERE hatm_id = pi_hatm_id;
    -- 
    RETURN (lv_cnt > 0);  
    --
  END mail_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION mail_exists(pi_hatm_halt_id   IN   hig_alert_type_mail.hatm_halt_id%TYPE)
  
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM hig_alert_type_mail
     WHERE hatm_halt_id = pi_hatm_halt_id;
    -- 
    RETURN (lv_cnt > 0);  
    --
  END mail_exists;
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_mail(pi_mail_id              IN     hig_alert_type_mail.hatm_id%TYPE
                       ,pi_alert_id             IN     hig_alert_type_mail.hatm_halt_id%TYPE
                       ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                       ,po_trigger_dropped         OUT varchar2
                       ,po_message_severity        OUT hig_codes.hco_code%TYPE
                       ,po_message_cursor          OUT sys_refcursor)

  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT delete_mail_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Mail Id'
                               ,pi_parameter_value => pi_mail_id);
    --
    IF NOT mail_exists(pi_hatm_id => pi_mail_id)
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Mail Id:  '||pi_mail_id);
    END IF;
    /*
    ||delete from hig_alert_type_mail.
    */
    DELETE 
      FROM hig_alert_type_mail
     WHERE hatm_id = pi_mail_id;
    --
    --Need to drop the trigger to be recreated--
    IF hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                             ,pi_trigger_name  => pi_trigger_name
                             ,po_error_text    => lv_error_text)
     THEN
        po_trigger_dropped := 'Y';  -- tells UI to display message to User
    ELSE   
        po_trigger_dropped := 'N';
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_mail_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_mail;  
                                                                                                                                                                                                                          
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE get_frequencies_lov(po_message_severity OUT  hig_codes.hco_code%TYPE
                               ,po_message_cursor   OUT  sys_refcursor
                               ,po_cursor           OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hsfr_frequency_id
          ,hsfr_meaning 
      FROM hig_scheduling_intervals_v 
    ORDER BY hsfr_interval_in_mins;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_frequencies_lov;                              
   
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE query_type_lov(po_message_severity OUT  hig_codes.hco_code%TYPE
                          ,po_message_cursor   OUT  sys_refcursor
                          ,po_cursor           OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nit_inv_type 
          ,nit_descr 
      FROM nm_inv_types
     WHERE nit_inv_type NOT IN (SELECT hfam_nit_inv_type FROM hig_flex_attribute_inv_mapping)  
    ORDER BY nit_inv_type;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END query_type_lov;
  
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE get_queries(po_message_severity OUT  hig_codes.hco_code%TYPE
                       ,po_message_cursor   OUT  sys_refcursor
                       ,po_cursor           OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hqt_id           query_id
          ,hqt_name         qry_name
          ,hqt_descr        qry_descr
          ,hqt_query_type   qry_type
          ,hqt_nit_inv_type inv_type 
          ,nit_descr        inv_type_descr
          ,hqt_created_by   owner_
          ,hqt_security     owner_filter  --Determines access rights for the query - Private (R) or Public (P).  Private queries are only be executed or amended by the owner.
          ,CASE 
             WHEN hqt_security = 'P' THEN 'Public'
             WHEN hqt_security = 'R' THEN 'Private'
           END              owner_filter_descr
          ,hqt_ignore_case  ignore_case
          ,hqt_where_clause where_clause
     from hig_query_types
         ,nm_inv_types
    WHERE hqt_nit_inv_type = nit_inv_type    
    ORDER BY UPPER(hqt_name);
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_queries;                         
   
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE get_paged_queries(pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                             ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                             ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                             ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                             ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                             ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                             ,pi_skip_n_rows          IN     PLS_INTEGER
                             ,pi_pagesize             IN     PLS_INTEGER
                             ,po_message_severity        OUT hig_codes.hco_code%TYPE
                             ,po_message_cursor          OUT sys_refcursor
                             ,po_cursor                  OUT sys_refcursor)
  IS
      --
      lv_order_by         nm3type.max_varchar2;
      lv_filter           nm3type.max_varchar2;
      --
      lv_cursor_sql  nm3type.max_varchar2 :='SELECT hqt_id           query_id'
                                                ||',hqt_name         qry_name'
                                                ||',hqt_descr        qry_descr'
                                                ||',hqt_query_type   qry_type'
                                                ||',hqt_nit_inv_type inv_type '
                                                ||',nit_descr        inv_type_descr'
                                                ||',hqt_created_by   owner_'
                                                ||',hqt_security     owner_filter'                                             
                                                ||',CASE 
                                                      WHEN hqt_security = ''P'' THEN ''Public''
                                                      WHEN hqt_security = ''R'' THEN ''Private''
                                                    END              owner_filter_descr'
                                                ||',hqt_ignore_case  ignore_case'
                                                ||',hqt_where_clause where_clause' 
                                                ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                           ||' FROM hig_query_types'
                                                ||',nm_inv_types'
                                          ||' WHERE hqt_nit_inv_type = nit_inv_type';
      --
      lt_column_data  awlrs_util.column_data_tab;
      --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_name'
                                ,pi_query_col    => 'hqt_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_descr'
                                ,pi_query_col    => 'hqt_descr'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'inv_type_descr'
                                ,pi_query_col    => 'nit_descr'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'owner_'
                                ,pi_query_col    => 'hqt_created_by'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'owner_filter_descr'
                                ,pi_query_col    => 'CASE 
                                                        WHEN hqt_security = ''P'' THEN ''Public''
                                                        WHEN hqt_security = ''R'' THEN ''Private''
                                                     END'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'UPPER(hqt_name)')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_queries;                                 
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION validate_query(pi_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                         ,pi_where_clause       IN     hig_query_types.hqt_where_clause%TYPE) RETURN BOOLEAN
                          
                             
  IS
  --
   lr_nit_rec           nm_inv_types%ROWTYPE;
   --
   lv_cursor_sql        nm3type.max_varchar2;
   lv_query_parsed      boolean;
   lv_error             varchar2(50);
  --
  BEGIN
    --
    lr_nit_rec     := nm3get.get_nit(pi_inv_type);
    --
    lv_cursor_sql := 'SELECT To_Char('||NVL(lr_nit_rec.nit_foreign_pk_column,'IIT_NE_ID')||') pk_col '||Chr(10)||
	                     'FROM '||NVL(lr_nit_rec.nit_table_name,'NM_INV_ITEMS_ALL');
	--
    IF pi_where_clause IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' '||pi_where_clause;
    END IF;
    --
    IF NVL(lr_nit_rec.nit_table_name,'NM_INV_ITEMS_ALL') = 'NM_INV_ITEMS_ALL'
	  THEN
	      IF INSTR(UPPER(lv_cursor_sql),'WHERE ') > 0
	      THEN	 
	          lv_cursor_sql := lv_cursor_sql ||CHR(10)||'AND iit_inv_type = '''||pi_inv_type||'''';
	      ELSE                                                                          
	          lv_cursor_sql := lv_cursor_sql ||CHR(10)||'WHERE iit_inv_type = '''||pi_inv_type||'''';
	      END IF;	   
	END IF;
	-- 
	lv_query_parsed := nm3flx.sql_parses_without_error(lv_cursor_sql,lv_error);
    --
	RETURN lv_query_parsed;
    --  
  EXCEPTION
    WHEN OTHERS
     THEN
        RETURN FALSE;
  END validate_query;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE build_query(pi_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                       ,pi_pre_bracket        IN     hig_query_type_attributes.hqta_pre_bracket%TYPE
                       ,pi_operator           IN     hig_query_type_attributes.hqta_operator%TYPE
                       ,pi_attribute_name     IN     hig_query_type_attributes.hqta_attribute_name%TYPE
                       ,pi_condition          IN     hig_query_type_attributes.hqta_condition%TYPE
                       ,pi_attribute_value    IN     hig_query_type_attributes.hqta_data_value%TYPE
                       ,pi_post_bracket       IN     hig_query_type_attributes.hqta_post_bracket%TYPE
                       ,pi_ignore_case        IN     hig_query_types.hqt_ignore_case%TYPE
                       ,po_where_clause       IN OUT hig_query_types.hqt_where_clause%TYPE 
                       ,po_message_severity      OUT hig_codes.hco_code%TYPE
                       ,po_message_cursor        OUT sys_refcursor
                       )
  IS
  --
   lv_where      hig_query_types.hqt_where_clause%TYPE; 
   lr_ita_rec    nm_inv_type_attribs%ROWTYPE;
   lv_value      hig_query_type_attributes.hqta_data_value%TYPE;
   lv_iit_attrib boolean;
  --
  BEGIN
    --
       lv_where := po_where_clause;
	   lv_iit_attrib := FALSE;
	   --
	    IF  pi_condition IS NOT NULL 	
	    AND pi_attribute_name IS NOT NULL
	    THEN
	        BEGIN
	            lr_ita_rec := nm3get.get_ita(pi_ita_inv_type => pi_inv_type,pi_ita_attrib_name => pi_attribute_name);
	        EXCEPTION
	         	  WHEN OTHERS THEN
	         	     lv_iit_attrib := TRUE;
	        END;
	    	  IF lv_where IS NOT NULL
	    	  THEN
	    	      IF NOT lv_iit_attrib
	            THEN
	    	          IF lr_ita_rec.ita_format = 'DATE'
    	    	      THEN
	        	          IF Upper(pi_condition) IN ('IS NULL','IS NOT NULL')
	    	              THEN	
	    	                  lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' Trunc('||pi_attribute_name||')  '||pi_condition||pi_post_bracket;
	    	              ELSE
	    	          	      lv_value := pi_attribute_value;
    	    	          	  IF Upper(lv_value) NOT LIKE '%SYSDATE%'
	        	          	  THEN
	    	              	      lv_value := 	''||pi_attribute_value||'' ;
	    	              	  END IF ;    
	    	              	  lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' Trunc('||pi_attribute_name||')  '||pi_condition||' '||lv_value||' '||pi_post_bracket;
    	    	          END IF ;	  
	        	      ELSE
	    	              IF Upper(pi_condition) IN ('IS NULL','IS NOT NULL')
	    	              THEN	
	    	      	          lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' '||pi_attribute_name||'  '||pi_condition||pi_post_bracket;
    	    	          ELSE
                          IF lr_ita_rec.ita_format = 'VARCHAR2'
	    	           	      THEN
	    	           	          IF pi_ignore_case  = 'Y'
	    	           	          THEN
	    	           	              lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' Upper('||pi_attribute_name||')  '||pi_condition||' '||Upper(pi_attribute_value)||''||pi_post_bracket; 
    	    	           	      ELSE
	        	       	              IF lr_ita_rec.ita_case = 'UPPER'
	    	           	       	      THEN	 
    	    	           	              lv_value := ''||Upper(pi_attribute_value)||'' ;	
	        	       	              ELSIF lr_ita_rec.ita_case = 'LOWER'
	    	           	           	  THEN	     
	    	           	       	          lv_value := ''||Lower(pi_attribute_value)||'' ;
	    	       	                  ELSE
	    	       	               	      lv_value := ''||pi_attribute_value||'' ;
	    	       	                  END IF ;	   
	    	       	                  lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' '||pi_attribute_name||'  '||pi_condition||' '||lv_value||' '||pi_post_bracket;
        	    	       	      END IF ;    
	        	       	      ELSE
	    	                      lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' '||pi_attribute_name||'  '||pi_condition||' '||pi_attribute_value||''||pi_post_bracket;
                          END IF ;	    	                  
    	    	          END IF ;    
    	    	      END IF ;    
	    	      ELSE
	    	          IF Upper(pi_condition) IN ('IS NULL','IS NOT NULL')
	    	          THEN	
	    	              lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' '||pi_attribute_name||'  '||pi_condition||pi_post_bracket;
    	    	      ELSE      	
	    	              lv_where := lv_where||Chr(10)||pi_operator||pi_pre_bracket||' '||pi_attribute_name||'  '||pi_condition||' '||pi_attribute_value||''||pi_post_bracket;	
	    	          END IF ;    
	    	      END IF ;	  
	    	  ELSE
	    	     IF NOT lv_iit_attrib
	            THEN	
	    	          IF lr_ita_rec.ita_format = 'DATE'
	    	          THEN
	    	              IF Upper(pi_condition) IN ('IS NULL','IS NOT NULL')
	    	              THEN 	
    	    	              lv_where := Chr(10)||'WHERE '||pi_pre_bracket||' Trunc('||pi_attribute_name||')  '||pi_condition||pi_post_bracket;
	        	          ELSE
	        	          	  lv_value := pi_attribute_value;
	    	              	  IF Upper(lv_value) NOT LIKE '%SYSDATE%'
	    	              	  THEN
	    	          	          lv_value := 	''||pi_attribute_value||'' ;
    	    	          	  END IF ;
	        	          	  lv_where := Chr(10)||'WHERE '||pi_pre_bracket||' Trunc('||pi_attribute_name||')  '||pi_condition||' '||lv_value||' '||pi_post_bracket;
	    	              END IF ; 	
	    	          ELSE
	    	              IF Upper(pi_condition) IN ('IS NULL','IS NOT NULL')
    	    	          THEN	
	        	      	      lv_where := Chr(10)||'WHERE '||pi_pre_bracket||pi_attribute_name||'  '||pi_condition||pi_post_bracket;
	    	              ELSE	    	              	  
	    	              	  IF lr_ita_rec.ita_format = 'VARCHAR2'
	    	       	          THEN
	    	       	              IF pi_ignore_case = 'Y'
	    	       	              THEN
	    	          	              lv_where := Chr(10)||'WHERE '||pi_pre_bracket||' Upper( '||pi_attribute_name||')  '||pi_condition||' '||Upper(pi_attribute_value)||''||pi_post_bracket;
	    	          	          ELSE
    	        	       	          IF lr_ita_rec.ita_case = 'UPPER'
	        	           	       	  THEN	 
	    	               	              lv_value := ''||Upper(pi_attribute_value)||'' ;
	    	               	          ELSIF lr_ita_rec.ita_case = 'LOWER'
	    	       	               	  THEN	     
	    	       	           	          lv_value := ''||Lower(pi_attribute_value)||'' ;
	    	       	           	      ELSE
    	    	       	           	      lv_value := ''||pi_attribute_value||'' ;
    	    	       	              END IF ;	   
	    	           	              lv_where := Chr(10)||'WHERE '||pi_pre_bracket||pi_attribute_name||'  '||pi_condition||' '||lv_value||' '||pi_post_bracket;
	    	           	          END IF ;    
	    	       	          ELSE
	    	          	          lv_where := Chr(10)||'WHERE '||pi_pre_bracket||pi_attribute_name||'  '||pi_condition||' '||pi_attribute_value||' '||pi_post_bracket;
    	    	          	  END IF ;    
	        	          END IF ; 	  
	    	          END IF ;	  
	    	      ELSE
	    	          IF Upper(pi_condition) IN ('IS NULL','IS NOT NULL')
    	    	      THEN	
	        	          lv_where := Chr(10)||'WHERE '||pi_pre_bracket||pi_attribute_name||'  '||pi_condition||pi_post_bracket;
	    	          ELSE     	
	    	              lv_where := Chr(10)||'WHERE '||pi_pre_bracket||pi_attribute_name||'  '||pi_condition||' '||pi_attribute_value||''||pi_post_bracket;    	
	    	          END IF ;    
	    	      END IF ;
	    	  END IF ;  	
	    END IF ;
	  
	  po_where_clause := lv_where;
      --  
      awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                           ,po_cursor           => po_message_cursor);
      --  
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);   
  END build_query;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE build_query(pi_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                       ,pi_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                       ,pi_operator           IN     nm3type.tab_varchar30
                       ,pi_attribute_name     IN     nm3type.tab_varchar30
                       ,pi_condition          IN     nm3type.tab_varchar30
                       ,pi_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                       ,pi_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                       ,pi_ignore_case        IN     hig_query_types.hqt_ignore_case%TYPE
                       ,po_where_clause          OUT hig_query_types.hqt_where_clause%TYPE 
                       ,po_message_severity   IN OUT hig_codes.hco_code%TYPE
                       ,po_message_tab        IN OUT NOCOPY awlrs_message_tab)
  IS
  --
   lv_attrib_value      hig_query_type_attributes.hqta_data_value%TYPE; 
   lv_where             hig_query_types.hqt_where_clause%TYPE; 
   lv_query_parsed      boolean;
   lv_message_severity  hig_codes.hco_code%TYPE;
   lv_message_cursor    sys_refcursor;
   --
   lt_messages  awlrs_util.message_tab;
  --
  BEGIN
    --
    IF pi_operator.COUNT != pi_pre_bracket.COUNT
    OR pi_operator.COUNT != pi_attribute_name.COUNT
    OR pi_operator.COUNT != pi_condition.COUNT
    OR pi_operator.COUNT != pi_attribute_value.COUNT
    OR pi_operator.COUNT != pi_post_bracket.COUNT
      THEN
        --The attribute tables passed in must have matching row counts
        hig.raise_ner(pi_appl               => 'AWLRS'
                     ,pi_id                 => 5
                     ,pi_supplementary_info => 'awlrs_alerts_api.build_query');
    END IF;  
    --
    IF pi_operator.COUNT > 0 
      THEN
        FOR i IN 1..pi_operator.COUNT LOOP
          --
          BEGIN  
             lv_attrib_value := dbms_assert.enquote_literal(pi_attribute_value(i));
          EXCEPTION
            when others then
                hig.raise_ner(pi_appl               => 'HIG'
                             ,pi_id                 => 444
                             ,pi_supplementary_info => 'For value '||pi_attribute_value(i)); 
          END;
          --
          build_query(pi_inv_type           =>  pi_inv_type
                     ,pi_pre_bracket        =>  pi_pre_bracket(i)
                     ,pi_operator           =>  pi_operator(i)
                     ,pi_attribute_name     =>  pi_attribute_name(i)
                     ,pi_condition          =>  pi_condition(i)
                     ,pi_attribute_value    =>  lv_attrib_value
                     ,pi_post_bracket       =>  pi_post_bracket(i)
                     ,pi_ignore_case        =>  pi_ignore_case
                     ,po_where_clause       =>  lv_where
                     ,po_message_severity   =>  lv_message_severity
                     ,po_message_cursor     =>  lv_message_cursor);  
        END LOOP;
        -- 
        lv_query_parsed := validate_query(pi_inv_type     => pi_inv_type
                                         ,pi_where_clause => lv_where);
                                                  
		IF NOT lv_query_parsed
		   THEN
		     hig.raise_ner(pi_appl => 'NET'
                          ,pi_id   => 121
                          ,pi_supplementary_info  => Null); 
	    END IF;
	    --
	    po_where_clause     := lv_where;
        --
        FETCH lv_message_cursor
         BULK COLLECT
         INTO lt_messages;
        CLOSE lv_message_cursor;
        --
        FOR i IN 1..lt_messages.COUNT LOOP
          --
          awlrs_util.add_message(pi_category    => lt_messages(i).category
                                ,pi_message     => lt_messages(i).message
                                ,po_message_tab => po_message_tab);
          --
        END LOOP;
        --
        
    --
    END IF;
    --
    
  END build_query;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_qry_attributes(pi_query_id           IN     hig_query_type_attributes.hqta_hqt_id%TYPE
                                 ,pi_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                 ,pi_pre_bracket        IN     hig_query_type_attributes.hqta_pre_bracket%TYPE
                                 ,pi_operator           IN     hig_query_type_attributes.hqta_operator%TYPE
                                 ,pi_attribute_name     IN     hig_query_type_attributes.hqta_attribute_name%TYPE
                                 ,pi_condition          IN     hig_query_type_attributes.hqta_condition%TYPE
                                 ,pi_attribute_value    IN     hig_query_type_attributes.hqta_data_value%TYPE
                                 ,pi_post_bracket       IN     hig_query_type_attributes.hqta_post_bracket%TYPE
                                 ,po_message_severity      OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor        OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT create_qry_attribs_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Query Id'
                               ,pi_parameter_value => pi_query_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Operator'
                               ,pi_parameter_value => pi_operator);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attribute Name'
                               ,pi_parameter_value => pi_attribute_name);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Condition'
                               ,pi_parameter_value => pi_condition);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Inv Type'
                               ,pi_parameter_value => pi_inv_type);
    --
    /*
    ||insert into hig_query_type_attributes.
    */
    INSERT
      INTO hig_query_type_attributes
          (hqta_id
          ,hqta_hqt_id
          ,hqta_pre_bracket
          ,hqta_operator
          ,hqta_attribute_name
          ,hqta_condition
          ,hqta_data_value
          ,hqta_post_bracket
          ,hqta_inv_type
          )
    VALUES (hqta_id_seq.NEXTVAL
           ,pi_query_id
           ,pi_pre_bracket
           ,pi_operator 
           ,pi_attribute_name
           ,pi_condition
           --,dbms_assert.enquote_literal(pi_attribute_value)
           ,pi_attribute_value
           ,pi_post_bracket
           ,pi_inv_type
           );
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_qry_attribs_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_qry_attributes;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_qry_attributes(pi_query_id           IN     hig_query_type_attributes.hqta_hqt_id%TYPE
                                 ,pi_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                 ,pi_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_operator           IN     nm3type.tab_varchar30
                                 ,pi_attribute_name     IN     nm3type.tab_varchar30
                                 ,pi_condition          IN     nm3type.tab_varchar30
                                 ,pi_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                                 ,pi_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,po_message_severity IN OUT hig_codes.hco_code%TYPE
                                 ,po_message_tab      IN OUT NOCOPY awlrs_message_tab)
  IS
    --
    lv_message_cursor  sys_refcursor;
    --
    lt_messages  awlrs_util.message_tab;
    --
  BEGIN
    --
    IF pi_operator.COUNT > 0 
       THEN
        FOR i IN 1..pi_operator.COUNT LOOP
            create_qry_attributes(pi_query_id         =>  pi_query_id
                                 ,pi_inv_type         =>  pi_inv_type
                                 ,pi_pre_bracket      =>  pi_pre_bracket(i)
                                 ,pi_operator         =>  pi_operator(i)
                                 ,pi_attribute_name   =>  pi_attribute_name(i)
                                 ,pi_condition        =>  pi_condition(i)
                                 ,pi_attribute_value  =>  pi_attribute_value(i)
                                 ,pi_post_bracket     =>  pi_post_bracket(i)
                                 ,po_message_severity =>  po_message_severity
                                 ,po_message_cursor   =>  lv_message_cursor);
            --
            FETCH lv_message_cursor
             BULK COLLECT
             INTO lt_messages;
            CLOSE lv_message_cursor;
            --
            FOR i IN 1..lt_messages.COUNT LOOP
              --
              awlrs_util.add_message(pi_category    => lt_messages(i).category
                                    ,pi_message     => lt_messages(i).message
                                    ,po_message_tab => po_message_tab);
              --
            END LOOP;
            --
            IF po_message_severity != awlrs_util.c_msg_cat_success
              THEN
              --
              lt_messages.DELETE;
              EXIT;
              --
            END IF;    
            -- 
        END LOOP;
    --
    END IF;
    --     
  END create_qry_attributes; 
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_query(pi_inv_type         IN     hig_query_types.hqt_nit_inv_type%TYPE
                        ,pi_qry_name         IN     hig_query_types.hqt_name%TYPE
                        ,pi_qry_descr        IN     hig_query_types.hqt_descr%TYPE
                        ,pi_owner_filter     IN     hig_query_types.hqt_security%TYPE
                        ,pi_ignore_case      IN     hig_query_types.hqt_ignore_case%TYPE
                        ,pi_where_clause     IN     hig_query_types.hqt_where_clause%TYPE
                        ,po_query_id            OUT hig_query_types.hqt_id%TYPE
                        ,po_message_severity    OUT hig_codes.hco_code%TYPE
                        ,po_message_cursor      OUT sys_refcursor)
  IS
  --
    lv_query_id hig_query_types.hqt_id%TYPE;
  --
  BEGIN
    --
    SAVEPOINT create_query_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Inv Type'
                               ,pi_parameter_value => pi_inv_type);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Name'
                               ,pi_parameter_value => pi_qry_name);
    --
    awlrs_util.validate_yn(pi_parameter_desc  => 'Ignore Case'
                          ,pi_parameter_value => pi_ignore_case);
    --
    IF NVL(pi_owner_filter, 'N') NOT IN ('P','R') THEN
        --
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 30
                     ,pi_supplementary_info => 'Owner Filter must be either P (Public) or R (Private)');
        --
    END IF;
    --    
    /*
    ||insert into hig_query_types.
    */
    SELECT hqt_id_seq.NEXTVAL
      INTO lv_query_id
      FROM dual;
    --
    INSERT
      INTO hig_query_types
          (hqt_id
          ,hqt_nit_inv_type
          ,hqt_name
          ,hqt_descr
          ,hqt_query_type
          ,hqt_security
          ,hqt_ignore_case
          ,hqt_where_clause 
          )
    VALUES (lv_query_id
           ,pi_inv_type
           ,pi_qry_name 
           ,pi_qry_descr
           ,'A'
           ,pi_owner_filter
           ,pi_ignore_case
           ,pi_where_clause          
           );
    --
    po_query_id := lv_query_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_query_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_query;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_query(pi_inv_type         IN     hig_query_types.hqt_nit_inv_type%TYPE
                        ,pi_qry_name         IN     hig_query_types.hqt_name%TYPE
                        ,pi_qry_descr        IN     hig_query_types.hqt_descr%TYPE
                        ,pi_owner_filter     IN     hig_query_types.hqt_security%TYPE
                        ,pi_ignore_case      IN     hig_query_types.hqt_ignore_case%TYPE
                        ,pi_where_clause     IN     hig_query_types.hqt_where_clause%TYPE
                        ,po_query_id            OUT hig_query_types.hqt_id%TYPE
                        ,po_message_severity IN OUT hig_codes.hco_code%TYPE
                        ,po_message_tab      IN OUT NOCOPY awlrs_message_tab)
  IS
    --
    lv_query_id hig_query_types.hqt_id%TYPE;
    lv_message_cursor  sys_refcursor;
    --
    lt_messages  awlrs_util.message_tab;
    --
  BEGIN
    --
    create_query(pi_inv_type          =>  pi_inv_type
                ,pi_qry_name          =>  pi_qry_name
                ,pi_qry_descr         =>  pi_qry_descr
                ,pi_owner_filter      =>  pi_owner_filter
                ,pi_ignore_case       =>  pi_ignore_case
                ,pi_where_clause      =>  pi_where_clause
                ,po_query_id          =>  po_query_id
                ,po_message_severity  =>  po_message_severity
                ,po_message_cursor    =>  lv_message_cursor);
    --
    FETCH lv_message_cursor
     BULK COLLECT
     INTO lt_messages;
    CLOSE lv_message_cursor;
    --
    FOR i IN 1..lt_messages.COUNT LOOP
      --
      awlrs_util.add_message(pi_category    => lt_messages(i).category
                            ,pi_message     => lt_messages(i).message
                            ,po_message_tab => po_message_tab);
      --
    END LOOP;
    
  END create_query; 
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_pk_column(pi_inv_type IN    nm_inv_types.nit_inv_type%TYPE 
                         ,po_col_name   OUT nm_inv_type_attribs.ita_attrib_name%TYPE
                         ,po_seq_no     OUT number)
  --
  IS
   
   lv_ita_rec  nm_inv_type_attribs%ROWTYPE;
   lv_pk_col   nm_inv_types.nit_foreign_pk_column%TYPE := NVL(nm3get.get_nit(pi_inv_type).nit_foreign_pk_column,'IIT_NE_ID'); 
   lv_seq_no   Number := 0 ;
   lv_col_name Varchar2(50);
--
BEGIN
--
   FOR i IN (SELECT *
             FROM   nm_inv_type_attribs
             WHERE  ita_inv_type    = pi_inv_type
             ORDER  BY ita_disp_seq_no)
   LOOP
       IF i.ita_displayed = 'Y'
       THEN
           lv_seq_no := lv_seq_no + 1;
       END IF ;
       IF  i.ita_attrib_name = lv_pk_col        
       AND i.ita_displayed = 'Y'
       THEN
           lv_col_name := i.ita_attrib_name ;
           po_seq_no   := lv_seq_no ;
           EXIT;
       ELSE
           lv_col_name := lv_pk_col ;
       END IF ;
   END LOOP;
   IF lv_col_name IS NOT NULL
   THEN 
       po_col_name := lv_col_name  ;
   ELSE
       po_col_name := 'IIT_NE_ID';
   END IF ;
  --
  END get_pk_column;
  --
  -----------------------------------------------------------------------------
  --
  --
  --Local copy of hig_nav.get_column_displayed due to the Navigator fmb requiring 168 cols to be returned regardless.--
  PROCEDURE get_column_displyed(pi_inv_type IN     nm_inv_types.nit_inv_type%TYPE
                               ,po_cols        OUT Varchar2
                               ,po_col_cnt     OUT Number)
  IS
  --
   lv_dis_cnt    Number ;
   lv_cnt        Number := 0 ;
   lv_col_name   nm_inv_type_attribs.ita_attrib_name%TYPE ;
   lv_seq_no     Number ;
   lv_reduce_cnt Number := 0 ;
  --
  BEGIN 
  --
   SELECT COUNT(*)
   INTO   lv_dis_cnt
   FROM   nm_inv_type_attribs
   WHERE  ita_inv_type  = pi_inv_type 
   AND    ita_displayed = 'Y';
   --
   IF lv_dis_cnt > 0
   THEN       
       FOR i IN (SELECT *
                 FROM   nm_inv_type_attribs
                 WHERE  ita_inv_type  = pi_inv_type 
                 AND    ita_displayed = 'Y'                 
                 ORDER BY ita_disp_seq_no)
       LOOP
           lv_cnt := lv_cnt + 1;
           IF i.ita_id_domain IS NOT NULL
           THEN
               po_cols := po_cols||',Substr(hig_nav.get_ial('''||i.ita_id_domain||''','||i.ita_attrib_name||'),1,500)'||'"'||i.ita_scrn_text||'"';
           ELSE
               IF i.ita_format = 'DATE'
               THEN
                   po_cols := po_cols||',To_Char(Trunc('||i.ita_attrib_name||'),''DD-Mon-YYYY'') '||'"'||i.ita_scrn_text||'"';
               ELSE
                   po_cols := po_cols||',Substr(To_Char('||i.ita_attrib_name||'),1,500) '||'"'||i.ita_scrn_text||'"';
               END IF ;
           END IF;
       END LOOP; 
   END IF ;
   get_pk_column (pi_inv_type 
                 ,lv_col_name 
                 ,lv_seq_no);
   IF lv_seq_no IS NULL
   THEN
       lv_reduce_cnt := 1;
       po_cols := po_cols||','||lv_col_name ;
   ELSE
       lv_reduce_cnt := 0;
   END IF ;
   --
   po_cols := Substr(po_cols,2);
   po_col_cnt  :=  lv_dis_cnt ;
   --
   END get_column_displyed; 
                      
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE run_query(pi_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                     ,pi_where_clause       IN     hig_query_types.hqt_where_clause%TYPE 
                     ,pi_sizelimit          IN     PLS_INTEGER
                     ,pi_result_set_only    IN     varchar2 
                     ,po_message_severity      OUT hig_codes.hco_code%TYPE
                     ,po_message_cursor        OUT sys_refcursor
                     ,po_cursor                OUT sys_refcursor)        
  IS
  --
   lr_nit_rec           nm_inv_types%ROWTYPE;
   --
   lv_cursor_sql        nm3type.max_varchar2;
   lv_where             hig_query_types.hqt_where_clause%TYPE;
   lv_display_col       nm3type.max_varchar2;
   lv_col_cnt           number;
   lv_query_parsed      boolean;
   lv_error             varchar2(50);
   lv_message_severity  hig_codes.hco_code%TYPE;
   lv_message_cursor    sys_refcursor;
   --
  --
  BEGIN
    --
    lr_nit_rec     := nm3get.get_nit(pi_inv_type);
    --
    IF pi_result_set_only = 'N'
      THEN
        lv_cursor_sql := 'SELECT To_Char('||NVL(lr_nit_rec.nit_foreign_pk_column,'IIT_NE_ID')||') pk_col '||Chr(10)||
	                     'FROM '||NVL(lr_nit_rec.nit_table_name,'NM_INV_ITEMS_ALL');
	ELSE                     
        get_column_displyed(pi_inv_type
                           ,lv_display_col
                           ,lv_col_cnt);
        --
        lv_cursor_sql := 'SELECT '||lv_display_col||Chr(10)|| 'FROM '||NVL(lr_nit_rec.nit_table_name,'NM_INV_ITEMS_ALL');
    END IF;	
    --
    IF pi_where_clause IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' '||pi_where_clause;
    END IF;
    --
    IF NVL(lr_nit_rec.nit_table_name,'NM_INV_ITEMS_ALL') = 'NM_INV_ITEMS_ALL'
	  THEN
	      IF INSTR(UPPER(lv_cursor_sql),'WHERE ') > 0
	      THEN	 
	          lv_cursor_sql := lv_cursor_sql ||CHR(10)||'AND iit_inv_type = '''||pi_inv_type||'''';
	      ELSE                                                                          
	          lv_cursor_sql := lv_cursor_sql ||CHR(10)||'WHERE iit_inv_type = '''||pi_inv_type||'''';
	      END IF;	   
	END IF;
	-- 
	lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_sizelimit||' ROWS ONLY ';
	--
	lv_query_parsed := nm3flx.sql_parses_without_error(lv_cursor_sql,lv_error);
	IF NOT lv_query_parsed
	  THEN
	    hig.raise_ner(pi_appl => 'NET'
                     ,pi_id   => 121
                     ,pi_supplementary_info  => Null); 
	END IF;  
	--
	OPEN po_cursor FOR lv_cursor_sql;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --  
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);           
  END run_query;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE run_query(pi_inv_type           IN     hig_query_types.hqt_nit_inv_type%TYPE
                     ,pi_ignore_case        IN     hig_query_types.hqt_ignore_case%TYPE
                     ,pi_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                     ,pi_operator           IN     nm3type.tab_varchar30
                     ,pi_attribute_name     IN     nm3type.tab_varchar30
                     ,pi_condition          IN     nm3type.tab_varchar30
                     ,pi_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                     ,pi_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                     ,pi_sizelimit          IN     PLS_INTEGER DEFAULT 15
                     ,pi_result_set_only    IN     varchar2 DEFAULT 'N'
                     ,po_message_severity      OUT hig_codes.hco_code%TYPE
                     ,po_message_cursor        OUT sys_refcursor
                     ,po_cursor                OUT sys_refcursor)
  IS
  --
    lv_query_id          hig_query_types.hqt_id%TYPE; 
    lv_where             hig_query_types.hqt_where_clause%TYPE; 
    lv_severity          hig_codes.hco_code%TYPE := awlrs_util.c_msg_cat_success;
    lv_message_cursor    sys_refcursor;
    --
    lt_messages  awlrs_message_tab := awlrs_message_tab();
    --
  BEGIN
    --
    awlrs_util.check_historic_mode; 
    --  
    build_query(pi_inv_type           =>  pi_inv_type
               ,pi_pre_bracket        =>  pi_pre_bracket
               ,pi_operator           =>  pi_operator
               ,pi_attribute_name     =>  pi_attribute_name
               ,pi_condition          =>  pi_condition
               ,pi_attribute_value    =>  pi_attribute_value
               ,pi_post_bracket       =>  pi_post_bracket
               ,pi_ignore_case        =>  pi_ignore_case
               ,po_where_clause       =>  lv_where
               ,po_message_severity   =>  lv_severity
               ,po_message_tab        =>  lt_messages);
    --
    IF lv_severity = awlrs_util.c_msg_cat_success
      THEN
        --
        lt_messages.DELETE;
        --  
        run_query(pi_inv_type          =>  pi_inv_type
                 ,pi_where_clause      =>  lv_where
                 ,pi_sizelimit         =>  pi_sizelimit
                 ,pi_result_set_only   =>  pi_result_set_only  
                 ,po_message_severity  =>  po_message_severity
                 ,po_message_cursor    =>  po_message_cursor
                 ,po_cursor            =>  po_cursor);
        --
    END IF;    
    -- 
  END run_query;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION query_exists(pi_hqt_id  IN  hig_query_types.hqt_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM hig_query_types
     WHERE hqt_id = hqt_id;
     
    RETURN (lv_cnt > 0);  
    --   
  END query_exists;
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_query(pi_query_id         IN     hig_query_types.hqt_id%TYPE
                        ,po_message_severity    OUT hig_codes.hco_code%TYPE
                        ,po_message_cursor      OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT delete_query_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Query Id'
                               ,pi_parameter_value => pi_query_id);
    --
    IF NOT query_exists(pi_hqt_id => pi_query_id) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Query Id:  '||pi_query_id);
    END IF;
    --
    /*
    ||delete from hig_query_type_attributes.
    */
    DELETE 
      FROM hig_query_type_attributes
     WHERE hqta_hqt_id = pi_query_id;
    /*
    ||delete from hig_query_types.
    */
    DELETE 
      FROM hig_query_types
     WHERE hqt_id = pi_query_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_query_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_query;   
                                           
  --
  -----------------------------------------------------------------------------
  -- 
  PROCEDURE get_qry_attributes(pi_query_id         IN      hig_query_type_attributes.hqta_hqt_id%TYPE
                              ,po_message_severity    OUT  hig_codes.hco_code%TYPE
                              ,po_message_cursor      OUT  sys_refcursor
                              ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hqta_id              qry_attrib_id
          ,hqta_hqt_id          query_id  
          ,hqta_pre_bracket     qry_pre_bracket
          ,hqta_operator        qry_operator
          ,hqta_attribute_name  qry_attrib_name
          ,ita_scrn_text        qry_attrib_name_descr
          ,hqta_condition       qry_condition 
          ,hqta_data_value      qry_data_value
          ,awlrs_alerts_api.get_cond_attrib_meaning(hqta_inv_type,hqta_attribute_name,hqta_data_value) data_value_meaning
          ,hqta_post_bracket    qry_post_bracket
          ,hqta_inv_type        inv_type
     from hig_query_type_attributes
         ,nm_inv_type_attribs_all
    WHERE hqta_hqt_id          = pi_query_id
      AND hqta_attribute_name  = ita_attrib_name(+)
      AND hqta_inv_type        = ita_inv_type(+)  
    ORDER BY hqta_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_qry_attributes;                               
 
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_qry_attribs(pi_query_id             IN      hig_query_type_attributes.hqta_hqt_id%TYPE
                                 ,pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                 ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                 ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                 ,pi_skip_n_rows          IN     PLS_INTEGER
                                 ,pi_pagesize             IN     PLS_INTEGER
                                 ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor          OUT sys_refcursor
                                 ,po_cursor                  OUT sys_refcursor)
  IS
      --
      lv_order_by         nm3type.max_varchar2;
      lv_filter           nm3type.max_varchar2;
      --
      lv_cursor_sql  nm3type.max_varchar2 :='SELECT hqta_id              qry_attrib_id'
                                                ||',hqta_hqt_id          query_id'
                                                ||',hqta_pre_bracket     qry_pre_bracket'
                                                ||',hqta_operator        qry_operator'
                                                ||',hqta_attribute_name  qry_attrib_name'
                                                ||',ita_scrn_text        qry_attrib_name_descr'
                                                ||',hqta_condition       qry_condition'
                                                ||',hqta_data_value      qry_data_value'
                                                ||',hqta_post_bracket    qry_post_bracket'
                                                ||',hqta_inv_type        inv_type'
                                                ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                           ||' FROM hig_query_type_attributes'
                                                ||',nm_inv_type_attribs_all'
                                          ||' WHERE hqta_hqt_id          = :pi_query_id'
                                          ||' AND hqta_attribute_name    = ita_attrib_name(+)'
                                          ||'  AND hqta_inv_type         = ita_inv_type(+)';
      --
      lt_column_data  awlrs_util.column_data_tab;
      --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_operator'
                                ,pi_query_col    => 'hqta_operator'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_pre_bracket'
                                ,pi_query_col    => 'hqta_pre_bracket'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_attrib_name_descr'
                                ,pi_query_col    => 'ita_scrn_text'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_condition'
                                ,pi_query_col    => 'hqta_condition'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_data_value'
                                ,pi_query_col    => 'hqta_data_value'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'attrib_value_meaning'
                                ,pi_query_col    => 'awlrs_alerts_api.get_cond_attrib_meaning(ita_inv_type,hatc_attribute_name,hatc_attribute_value)'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'qry_post_bracket'
                                ,pi_query_col    => 'hqta_post_bracket'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'hqta_id')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql
    USING pi_query_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_qry_attribs;   
                               
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION qry_attrib_exists(pi_hqta_id    IN   hig_query_type_attributes.hqta_id%TYPE)                             
  RETURN BOOLEAN
  IS
    lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*)
      INTO lv_cnt
      FROM hig_query_type_attributes
     WHERE hqta_id = pi_hqta_id; 
    --
    RETURN (lv_cnt > 0);  
    --
  END qry_attrib_exists;
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_qry_attributes(pi_qry_attribs_id     IN     hig_query_type_attributes.hqta_id%TYPE
                                 ,po_message_severity      OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor        OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT delete_qry_attribs_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Query Attributes Id'
                               ,pi_parameter_value => pi_qry_attribs_id);
    --
    IF NOT qry_attrib_exists(pi_hqta_id => pi_qry_attribs_id) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Query Attributes Id:  '||pi_qry_attribs_id);
    END IF;
    --
    /*
    ||delete from hig_query_type_attributes.
    */
    DELETE 
      FROM hig_query_type_attributes
     WHERE hqta_id = pi_qry_attribs_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_qry_attribs_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_qry_attributes;   
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE save_query_and_attribs(pi_inv_type           IN     hig_query_types.hqt_nit_inv_type%TYPE
                                  ,pi_qry_name           IN     hig_query_types.hqt_name%TYPE
                                  ,pi_qry_descr          IN     hig_query_types.hqt_descr%TYPE
                                  ,pi_owner_filter       IN     hig_query_types.hqt_security%TYPE
                                  ,pi_ignore_case        IN     hig_query_types.hqt_ignore_case%TYPE
                                  ,pi_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                  ,pi_operator           IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                  ,pi_attribute_name     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                  ,pi_condition          IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                  ,pi_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                                  ,pi_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                  ,po_query_id              OUT hig_query_types.hqt_id%TYPE
                                  ,po_message_severity      OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor        OUT sys_refcursor)
  IS
  --
    lv_query_id          hig_query_types.hqt_id%TYPE; 
    lv_where             hig_query_types.hqt_where_clause%TYPE; 
    lv_severity          hig_codes.hco_code%TYPE := awlrs_util.c_msg_cat_success;
    lv_message_cursor    sys_refcursor;
    --
    lt_messages  awlrs_message_tab := awlrs_message_tab();
    --
  BEGIN
    --
    SAVEPOINT save_query_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    --firstly we need to build the hqt_where_clause based on the data that will be saved in hig_query_type_attributes
    build_query(pi_inv_type           =>  pi_inv_type
               ,pi_pre_bracket        =>  pi_pre_bracket
               ,pi_operator           =>  pi_operator
               ,pi_attribute_name     =>  pi_attribute_name
               ,pi_condition          =>  pi_condition
               ,pi_attribute_value    =>  pi_attribute_value
               ,pi_post_bracket       =>  pi_post_bracket
               ,pi_ignore_case        =>  pi_ignore_case
               ,po_where_clause       =>  lv_where
               ,po_message_severity   =>  lv_severity
               ,po_message_tab        =>  lt_messages);
    --
    IF lv_severity = awlrs_util.c_msg_cat_success
      THEN
        --
        lt_messages.DELETE;
        --  
        create_query(pi_inv_type          =>  pi_inv_type
                    ,pi_qry_name          =>  pi_qry_name
                    ,pi_qry_descr         =>  pi_qry_descr
                    ,pi_owner_filter      =>  pi_owner_filter
                    ,pi_ignore_case       =>  pi_ignore_case
                    ,pi_where_clause      =>  lv_where
                    ,po_query_id          =>  lv_query_id
                    ,po_message_severity  =>  lv_severity
                    ,po_message_tab       =>  lt_messages);
    --
    END IF;  
    --
    IF lv_severity = awlrs_util.c_msg_cat_success
      THEN
        --
        lt_messages.DELETE;
        --
        create_qry_attributes(pi_query_id         =>  lv_query_id
                             ,pi_inv_type         =>  pi_inv_type
                             ,pi_pre_bracket      =>  pi_pre_bracket
                             ,pi_operator         =>  pi_operator
                             ,pi_attribute_name   =>  pi_attribute_name
                             ,pi_condition        =>  pi_condition
                             ,pi_attribute_value  =>  pi_attribute_value
                             ,pi_post_bracket     =>  pi_post_bracket
                             ,po_message_severity =>  lv_severity
                             ,po_message_tab      =>  lt_messages);
    --          
    END IF;  
    --
    IF lt_messages.COUNT > 0
     THEN
        --
        awlrs_util.get_message_cursor(pi_message_tab => lt_messages
                                     ,po_cursor      => po_message_cursor);
        --                             
        awlrs_util.get_highest_severity(pi_message_tab      => lt_messages
                                       ,po_message_severity => po_message_severity);
        --                               
    ELSE
        --
        po_query_id := lv_query_id;
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --                                     
    END IF;
    
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO save_query_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END save_query_and_attribs;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_query(pi_old_query_id         IN     hig_query_types.hqt_id%TYPE
                        ,pi_old_inv_type         IN     hig_query_types.hqt_nit_inv_type%TYPE
                        ,pi_old_qry_name         IN     hig_query_types.hqt_name%TYPE
                        ,pi_old_qry_descr        IN     hig_query_types.hqt_descr%TYPE
                        ,pi_old_qry_type         IN     hig_query_types.hqt_query_type%TYPE
                        ,pi_old_owner_filter     IN     hig_query_types.hqt_security%TYPE
                        ,pi_old_ignore_case      IN     hig_query_types.hqt_ignore_case%TYPE
                        ,pi_old_where_clause     IN     hig_query_types.hqt_where_clause%TYPE
                        ,pi_new_inv_type         IN     hig_query_types.hqt_nit_inv_type%TYPE
                        ,pi_new_qry_descr        IN     hig_query_types.hqt_descr%TYPE
                        ,pi_new_owner_filter     IN     hig_query_types.hqt_security%TYPE
                        ,pi_new_ignore_case      IN     hig_query_types.hqt_ignore_case%TYPE
                        ,pi_new_where_clause     IN     hig_query_types.hqt_where_clause%TYPE
                        ,po_message_severity        OUT hig_codes.hco_code%TYPE
                        ,po_message_cursor          OUT sys_refcursor)
  IS
    --
    lr_db_rec        hig_query_types%ROWTYPE;
    lv_upd           VARCHAR2(1) := 'N';
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_query_types
       WHERE hqt_id = pi_old_query_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Query Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_query_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
        hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Inv Type'
                               ,pi_parameter_value => pi_new_inv_type);
    --
    awlrs_util.validate_yn(pi_parameter_desc  => 'Ignore Case'
                          ,pi_parameter_value => pi_new_ignore_case);
    --
    IF NVL(pi_new_owner_filter, 'N') NOT IN ('P','R') THEN
        --
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 30
                     ,pi_supplementary_info => 'Owner Filter must be either P (Public) or R (Private)');
        --
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.hqt_id != pi_old_query_id
     OR (lr_db_rec.hqt_id IS NULL AND pi_old_query_id IS NOT NULL)
     OR (lr_db_rec.hqt_id IS NOT NULL AND pi_old_query_id IS NULL)
     --
     OR (lr_db_rec.hqt_nit_inv_type != pi_old_inv_type)
     OR (lr_db_rec.hqt_nit_inv_type IS NULL AND pi_old_inv_type IS NOT NULL)
     OR (lr_db_rec.hqt_nit_inv_type IS NOT NULL AND pi_old_inv_type IS NULL)
     --
     OR (UPPER(lr_db_rec.hqt_name) != UPPER(pi_old_qry_name))
     OR (UPPER(lr_db_rec.hqt_name) IS NULL AND UPPER(pi_old_qry_name) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqt_name) IS NOT NULL AND UPPER(pi_old_qry_name) IS NULL)
     --
     OR (UPPER(lr_db_rec.hqt_descr) != UPPER(pi_old_qry_descr))
     OR (UPPER(lr_db_rec.hqt_descr) IS NULL AND UPPER(pi_old_qry_descr) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqt_descr) IS NOT NULL AND UPPER(pi_old_qry_descr) IS NULL)
     --
     OR (UPPER(lr_db_rec.hqt_query_type) != UPPER(pi_old_qry_type))
     OR (UPPER(lr_db_rec.hqt_query_type) IS NULL AND UPPER(pi_old_qry_type) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqt_query_type) IS NOT NULL AND UPPER(pi_old_qry_type) IS NULL)
     --
     OR (UPPER(lr_db_rec.hqt_security) != UPPER(pi_old_owner_filter))
     OR (UPPER(lr_db_rec.hqt_security) IS NULL AND UPPER(pi_old_owner_filter) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqt_security) IS NOT NULL AND UPPER(pi_old_owner_filter) IS NULL)
     --
     OR (UPPER(lr_db_rec.hqt_ignore_case) != UPPER(pi_old_ignore_case))
     OR (UPPER(lr_db_rec.hqt_ignore_case) IS NULL AND UPPER(pi_old_ignore_case) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqt_ignore_case) IS NOT NULL AND UPPER(pi_old_ignore_case) IS NULL)
     --
     --NB this is derived from the hig_query_type_attributes
     OR (UPPER(lr_db_rec.hqt_where_clause) != UPPER(pi_old_where_clause))
     OR (UPPER(lr_db_rec.hqt_where_clause) IS NULL AND UPPER(pi_old_where_clause) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqt_where_clause) IS NOT NULL AND UPPER(pi_old_where_clause) IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF pi_old_inv_type != pi_new_inv_type
       OR (pi_old_inv_type IS NULL AND pi_new_inv_type IS NOT NULL)
       OR (pi_old_inv_type IS NOT NULL AND pi_new_inv_type IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_qry_descr) != UPPER(pi_new_qry_descr)
       OR (UPPER(pi_old_qry_descr) IS NULL AND UPPER(pi_new_qry_descr) IS NOT NULL)
       OR (UPPER(pi_old_qry_descr) IS NOT NULL AND UPPER(pi_new_qry_descr) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_owner_filter) != UPPER(pi_new_owner_filter)
       OR (UPPER(pi_old_owner_filter) IS NULL AND UPPER(pi_new_owner_filter) IS NOT NULL)
       OR (UPPER(pi_old_owner_filter) IS NOT NULL AND UPPER(pi_new_owner_filter) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_ignore_case) != UPPER(pi_new_ignore_case)
       OR (UPPER(pi_old_ignore_case) IS NULL AND UPPER(pi_new_ignore_case) IS NOT NULL)
       OR (UPPER(pi_old_ignore_case) IS NOT NULL AND UPPER(pi_new_ignore_case) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_new_where_clause IS NOT NULL  --just assume changes have been made
      --IF UPPER(pi_old_where_clause) != UPPER(pi_new_where_clause)
      -- OR (UPPER(pi_old_where_clause) IS NULL AND UPPER(pi_new_where_clause) IS NOT NULL)
      -- OR (UPPER(pi_old_where_clause) IS NOT NULL AND UPPER(pi_new_where_clause) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_query_types
           SET hqt_nit_inv_type = pi_new_inv_type
              ,hqt_descr        = pi_new_qry_descr
              ,hqt_query_type   = 'A'
              ,hqt_security     = hqt_security
              ,hqt_ignore_case  = pi_new_ignore_case
              ,hqt_where_clause = pi_new_where_clause
         WHERE hqt_id           = pi_old_query_id;
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF;
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_query_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_query;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_query(pi_old_query_id         IN     hig_query_types.hqt_id%TYPE
                        ,pi_old_inv_type         IN     hig_query_types.hqt_nit_inv_type%TYPE
                        ,pi_old_qry_name         IN     hig_query_types.hqt_name%TYPE
                        ,pi_old_qry_descr        IN     hig_query_types.hqt_descr%TYPE
                        ,pi_old_qry_type         IN     hig_query_types.hqt_query_type%TYPE
                        ,pi_old_owner_filter     IN     hig_query_types.hqt_security%TYPE
                        ,pi_old_ignore_case      IN     hig_query_types.hqt_ignore_case%TYPE
                        ,pi_old_where_clause     IN     hig_query_types.hqt_where_clause%TYPE
                        ,pi_new_inv_type         IN     hig_query_types.hqt_nit_inv_type%TYPE
                        ,pi_new_qry_descr        IN     hig_query_types.hqt_descr%TYPE
                        ,pi_new_owner_filter     IN     hig_query_types.hqt_security%TYPE
                        ,pi_new_ignore_case      IN     hig_query_types.hqt_ignore_case%TYPE
                        ,pi_new_where_clause     IN     hig_query_types.hqt_where_clause%TYPE
                        ,po_message_severity     IN OUT hig_codes.hco_code%TYPE
                        ,po_message_tab          IN OUT NOCOPY awlrs_message_tab)
  IS
    --
    lv_message_cursor  sys_refcursor;
    --
    lt_messages  awlrs_util.message_tab;
    --
  BEGIN
    --
    update_query(pi_old_query_id      =>  pi_old_query_id
                ,pi_old_inv_type      =>  pi_old_inv_type    
                ,pi_old_qry_name      =>  pi_old_qry_name 
                ,pi_old_qry_descr     =>  pi_old_qry_descr 
                ,pi_old_qry_type      =>  pi_old_qry_type 
                ,pi_old_owner_filter  =>  pi_old_owner_filter 
                ,pi_old_ignore_case   =>  pi_old_ignore_case 
                ,pi_old_where_clause  =>  pi_old_where_clause 
                ,pi_new_inv_type      =>  pi_new_inv_type 
                ,pi_new_qry_descr     =>  pi_new_qry_descr
                ,pi_new_owner_filter  =>  pi_new_owner_filter
                ,pi_new_ignore_case   =>  pi_new_ignore_case
                ,pi_new_where_clause  =>  pi_new_where_clause
                ,po_message_severity  =>  po_message_severity
                ,po_message_cursor    =>  lv_message_cursor);
    --
    FETCH lv_message_cursor
     BULK COLLECT
     INTO lt_messages;
    CLOSE lv_message_cursor;
    --
    FOR i IN 1..lt_messages.COUNT LOOP
      --
      awlrs_util.add_message(pi_category    => lt_messages(i).category
                            ,pi_message     => lt_messages(i).message
                            ,po_message_tab => po_message_tab);
      --
    END LOOP;
    
  END update_query;
  
  PROCEDURE update_qry_attributes(pi_old_qry_attrib_id      IN     hig_query_type_attributes.hqta_id%TYPE
                                 ,pi_old_query_id           IN     hig_query_type_attributes.hqta_hqt_id%TYPE
                                 ,pi_old_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                 ,pi_old_pre_bracket        IN     hig_query_type_attributes.hqta_pre_bracket%TYPE
                                 ,pi_old_operator           IN     hig_query_type_attributes.hqta_operator%TYPE
                                 ,pi_old_attribute_name     IN     hig_query_type_attributes.hqta_attribute_name%TYPE
                                 ,pi_old_condition          IN     hig_query_type_attributes.hqta_condition%TYPE
                                 ,pi_old_attribute_value    IN     hig_query_type_attributes.hqta_data_value%TYPE
                                 ,pi_old_post_bracket       IN     hig_query_type_attributes.hqta_post_bracket%TYPE
                                 ,pi_new_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                 ,pi_new_pre_bracket        IN     hig_query_type_attributes.hqta_pre_bracket%TYPE
                                 ,pi_new_operator           IN     hig_query_type_attributes.hqta_operator%TYPE
                                 ,pi_new_attribute_name     IN     hig_query_type_attributes.hqta_attribute_name%TYPE
                                 ,pi_new_condition          IN     hig_query_type_attributes.hqta_condition%TYPE
                                 ,pi_new_attribute_value    IN     hig_query_type_attributes.hqta_data_value%TYPE
                                 ,pi_new_post_bracket       IN     hig_query_type_attributes.hqta_post_bracket%TYPE
                                 ,po_message_severity          OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor            OUT sys_refcursor)
   IS
    --
    lr_db_rec        hig_query_type_attributes%ROWTYPE;
    lv_upd           varchar2(1) := 'N';
    lv_error_text    varchar2(32767);
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_query_type_attributes
       WHERE hqta_id = pi_old_qry_attrib_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_qry_attribs_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Operator'
                               ,pi_parameter_value => pi_new_operator);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Attribute Name'
                               ,pi_parameter_value => pi_new_attribute_name);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Condition'
                               ,pi_parameter_value => pi_new_condition);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Inv Type'
                               ,pi_parameter_value => pi_new_inv_type);
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
   IF lr_db_rec.hqta_id != pi_old_qry_attrib_id
     OR (lr_db_rec.hqta_id IS NULL AND pi_old_qry_attrib_id IS NOT NULL)
     OR (lr_db_rec.hqta_id IS NOT NULL AND pi_old_qry_attrib_id IS NULL)
     --
     OR (lr_db_rec.hqta_hqt_id != pi_old_query_id)
     OR (lr_db_rec.hqta_hqt_id IS NULL AND pi_old_query_id IS NOT NULL)
     OR (lr_db_rec.hqta_hqt_id IS NOT NULL AND pi_old_query_id IS NULL)
     --
     OR (lr_db_rec.hqta_operator != pi_old_operator)
     OR (lr_db_rec.hqta_operator IS NULL AND pi_old_operator IS NOT NULL)
     OR (lr_db_rec.hqta_operator IS NOT NULL AND pi_old_operator IS NULL)
     --
     OR (lr_db_rec.hqta_pre_bracket != pi_old_pre_bracket)
     OR (lr_db_rec.hqta_pre_bracket IS NULL AND pi_old_pre_bracket IS NOT NULL)
     OR (lr_db_rec.hqta_pre_bracket IS NOT NULL AND pi_old_pre_bracket IS NULL)
     --
     OR (UPPER(lr_db_rec.hqta_attribute_name) != UPPER(pi_old_attribute_name))
     OR (UPPER(lr_db_rec.hqta_attribute_name) IS NULL AND UPPER(pi_old_attribute_name) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqta_attribute_name) IS NOT NULL AND UPPER(pi_old_attribute_name) IS NULL)
     --
     OR (lr_db_rec.hqta_condition != pi_old_condition)
     OR (lr_db_rec.hqta_condition IS NULL AND pi_old_condition IS NOT NULL)
     OR (lr_db_rec.hqta_condition IS NOT NULL AND pi_old_condition IS NULL)
     --
     OR (UPPER(lr_db_rec.hqta_data_value) != UPPER(pi_old_attribute_value))
     OR (UPPER(lr_db_rec.hqta_data_value) IS NULL AND UPPER(pi_old_attribute_value) IS NOT NULL)
     OR (UPPER(lr_db_rec.hqta_data_value) IS NOT NULL AND UPPER(pi_old_attribute_value) IS NULL)
     --
     OR (lr_db_rec.hqta_post_bracket != pi_old_post_bracket)
     OR (lr_db_rec.hqta_post_bracket IS NULL AND pi_old_post_bracket IS NOT NULL)
     OR (lr_db_rec.hqta_post_bracket IS NOT NULL AND pi_old_post_bracket IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      lv_upd := 'Y';  --replace all
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_query_type_attributes
           SET hqta_operator        = pi_new_operator
              ,hqta_pre_bracket     = pi_new_pre_bracket
              ,hqta_attribute_name  = UPPER(pi_new_attribute_name)
              ,hqta_condition       = pi_new_condition
              ,hqta_data_value      = UPPER(pi_new_attribute_value)
              ,hqta_post_bracket    = pi_new_post_bracket
         WHERE hqta_id              = pi_old_qry_attrib_id;          
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF; 
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_qry_attribs_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_qry_attributes;                                                    
 
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_qry_attributes(pi_old_qry_attrib_id      IN     nm3type.tab_number
                                 ,pi_old_query_id           IN     hig_query_type_attributes.hqta_hqt_id%TYPE
                                 ,pi_old_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                 ,pi_old_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_old_operator           IN     nm3type.tab_varchar30
                                 ,pi_old_attribute_name     IN     nm3type.tab_varchar30
                                 ,pi_old_condition          IN     nm3type.tab_varchar30
                                 ,pi_old_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                                 ,pi_old_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_new_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                 ,pi_new_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_new_operator           IN     nm3type.tab_varchar30
                                 ,pi_new_attribute_name     IN     nm3type.tab_varchar30
                                 ,pi_new_condition          IN     nm3type.tab_varchar30
                                 ,pi_new_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                                 ,pi_new_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,po_message_severity       IN OUT hig_codes.hco_code%TYPE
                                 ,po_message_tab            IN OUT NOCOPY awlrs_message_tab)
  IS
    --
    lv_int             number;
    lv_iud_flag        varchar2(1);
    lv_message_cursor  sys_refcursor;
    --
    lt_messages  awlrs_util.message_tab;
    --
  BEGIN
    --
    IF pi_old_operator.COUNT = pi_new_operator.COUNT
      THEN
         lv_int := pi_old_operator.COUNT;
         lv_iud_flag := 'U';
    ELSIF
       pi_old_operator.COUNT > pi_new_operator.COUNT
       THEN
         lv_int := pi_new_operator.COUNT;
         lv_iud_flag := 'D';  --delete existing records
    ELSIF 
       pi_old_operator.COUNT < pi_new_operator.COUNT
       THEN 
         lv_int := pi_old_operator.COUNT;
         lv_iud_flag := 'I';  --insert new records 
    END IF;
    --
    FOR i IN 1..lv_int LOOP
           update_qry_attributes(pi_old_qry_attrib_id     =>  pi_old_qry_attrib_id(i)
                                ,pi_old_query_id          =>  pi_old_query_id
                                ,pi_old_inv_type          =>  pi_old_inv_type
                                ,pi_old_pre_bracket       =>  pi_old_pre_bracket(i)
                                ,pi_old_operator          =>  pi_old_operator(i)
                                ,pi_old_attribute_name    =>  pi_old_attribute_name(i)
                                ,pi_old_condition         =>  pi_old_condition(i)
                                ,pi_old_attribute_value   =>  pi_old_attribute_value(i)
                                ,pi_old_post_bracket      =>  pi_old_post_bracket(i)
                                ,pi_new_inv_type          =>  pi_new_inv_type
                                ,pi_new_pre_bracket       =>  pi_new_pre_bracket(i)
                                ,pi_new_operator          =>  pi_new_operator(i)
                                ,pi_new_attribute_name    =>  pi_new_attribute_name(i)
                                ,pi_new_condition         =>  pi_new_condition(i)
                                ,pi_new_attribute_value   =>  pi_new_attribute_value(i)
                                ,pi_new_post_bracket      =>  pi_new_post_bracket(i)
                                ,po_message_severity      =>  po_message_severity
                                ,po_message_cursor        =>  lv_message_cursor);
        --
        FETCH lv_message_cursor
         BULK COLLECT
         INTO lt_messages;
        CLOSE lv_message_cursor;
        --
        FOR i IN 1..lt_messages.COUNT LOOP
          --
          awlrs_util.add_message(pi_category    => lt_messages(i).category
                                ,pi_message     => lt_messages(i).message
                                ,po_message_tab => po_message_tab);
          --
        END LOOP;
        --
        IF po_message_severity != awlrs_util.c_msg_cat_success
          THEN
          --
          lt_messages.DELETE;
          EXIT;
          --
        END IF;    
        -- 
    END LOOP;
    --
    IF lv_iud_flag = 'I'  -- now need to insert new attribute records
      THEN
        FOR i IN lv_int + 1..pi_new_operator.COUNT LOOP
            create_qry_attributes(pi_query_id         =>  pi_old_query_id
                                 ,pi_inv_type         =>  pi_new_inv_type
                                 ,pi_pre_bracket      =>  pi_new_pre_bracket(i)
                                 ,pi_operator         =>  pi_new_operator(i)
                                 ,pi_attribute_name   =>  pi_new_attribute_name(i)
                                 ,pi_condition        =>  pi_new_condition(i)
                                 ,pi_attribute_value  =>  pi_new_attribute_value(i)
                                 ,pi_post_bracket     =>  pi_new_post_bracket(i)
                                 ,po_message_severity =>  po_message_severity
                                 ,po_message_cursor   =>  lv_message_cursor);
            --
            FETCH lv_message_cursor
             BULK COLLECT
             INTO lt_messages;
            CLOSE lv_message_cursor;
            --
            FOR i IN 1..lt_messages.COUNT LOOP
              --
              awlrs_util.add_message(pi_category    => lt_messages(i).category
                                    ,pi_message     => lt_messages(i).message
                                    ,po_message_tab => po_message_tab);
              --
            END LOOP;
            --
            IF po_message_severity != awlrs_util.c_msg_cat_success
              THEN
              --
              lt_messages.DELETE;
              EXIT;
              --
            END IF;    
            -- 
        END LOOP; 
    ELSE
      IF lv_iud_flag = 'D'
      THEN
         FOR i IN lv_int + 1..pi_old_operator.COUNT LOOP
            delete_qry_attributes(pi_qry_attribs_id    => pi_old_qry_attrib_id(i)
                                 ,po_message_severity =>  po_message_severity
                                 ,po_message_cursor   =>  lv_message_cursor);
         --
            FETCH lv_message_cursor
             BULK COLLECT
             INTO lt_messages;
            CLOSE lv_message_cursor;
            --
            FOR i IN 1..lt_messages.COUNT LOOP
              --
              awlrs_util.add_message(pi_category    => lt_messages(i).category
                                    ,pi_message     => lt_messages(i).message
                                    ,po_message_tab => po_message_tab);
              --
            END LOOP;
            --
            IF po_message_severity != awlrs_util.c_msg_cat_success
              THEN
              --
              lt_messages.DELETE;
              EXIT;
              --
            END IF;    
            -- 
        END LOOP;                        

      END IF;    
    END IF;
    
  END update_qry_attributes;
    
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_query_and_attribs(pi_old_query_id           IN     hig_query_type_attributes.hqta_hqt_id%TYPE
                                    ,pi_old_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                    ,pi_old_qry_name           IN     hig_query_types.hqt_name%TYPE
                                    ,pi_old_qry_descr          IN     hig_query_types.hqt_descr%TYPE
                                    ,pi_old_qry_type           IN     hig_query_types.hqt_query_type%TYPE
                                    ,pi_old_owner_filter       IN     hig_query_types.hqt_security%TYPE
                                    ,pi_old_ignore_case        IN     hig_query_types.hqt_ignore_case%TYPE
                                    ,pi_old_where_clause       IN     hig_query_types.hqt_where_clause%TYPE
                                    ,pi_old_qry_attrib_id      IN     nm3type.tab_number
                                    ,pi_old_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_old_operator           IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_old_attribute_name     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30) 
                                    ,pi_old_condition          IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_old_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                                    ,pi_old_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_new_inv_type           IN     hig_query_type_attributes.hqta_inv_type%TYPE
                                    ,pi_new_qry_descr          IN     hig_query_types.hqt_descr%TYPE
                                    ,pi_new_owner_filter       IN     hig_query_types.hqt_security%TYPE
                                    ,pi_new_ignore_case        IN     hig_query_types.hqt_ignore_case%TYPE
                                    ,pi_new_pre_bracket        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_new_operator           IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_new_attribute_name     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_new_condition          IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                    ,pi_new_attribute_value    IN     nm3type.tab_varchar2000 DEFAULT CAST(NULL AS nm3type.tab_varchar2000)
                                    ,pi_new_post_bracket       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)        
                                    ,po_message_severity      OUT hig_codes.hco_code%TYPE
                                    ,po_message_cursor        OUT sys_refcursor)
  
  IS
  --
    lv_query_id          hig_query_types.hqt_id%TYPE; 
    lv_where             hig_query_types.hqt_where_clause%TYPE; 
    lv_severity    hig_codes.hco_code%TYPE := awlrs_util.c_msg_cat_success;
    lv_message_cursor    sys_refcursor;
    
    lt_messages  awlrs_message_tab := awlrs_message_tab();
   --
  BEGIN
    --
    SAVEPOINT update_query_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    --firstly we need to build the hqt_where_clause based on the data that will be saved in hig_query_type_attributes
    build_query(pi_inv_type           =>  pi_new_inv_type
               ,pi_pre_bracket        =>  pi_new_pre_bracket
               ,pi_operator           =>  pi_new_operator
               ,pi_attribute_name     =>  pi_new_attribute_name
               ,pi_condition          =>  pi_new_condition
               ,pi_attribute_value    =>  pi_new_attribute_value
               ,pi_post_bracket       =>  pi_new_post_bracket
               ,pi_ignore_case        =>  pi_new_ignore_case
               ,po_where_clause       =>  lv_where
               ,po_message_severity   =>  lv_severity
               ,po_message_tab        =>  lt_messages);
    --
    IF lv_severity = awlrs_util.c_msg_cat_success
      THEN
        --
        lt_messages.DELETE;
        --
        update_query(pi_old_query_id      =>  pi_old_query_id
                    ,pi_old_inv_type      =>  pi_old_inv_type    
                    ,pi_old_qry_name      =>  pi_old_qry_name 
                    ,pi_old_qry_descr     =>  pi_old_qry_descr 
                    ,pi_old_qry_type      =>  pi_old_qry_type 
                    ,pi_old_owner_filter  =>  pi_old_owner_filter 
                    ,pi_old_ignore_case   =>  pi_old_ignore_case 
                    ,pi_old_where_clause  =>  pi_old_where_clause 
                    ,pi_new_inv_type      =>  pi_new_inv_type 
                    ,pi_new_qry_descr     =>  pi_new_qry_descr
                    ,pi_new_owner_filter  =>  pi_new_owner_filter
                    ,pi_new_ignore_case   =>  pi_new_ignore_case
                    ,pi_new_where_clause  =>  lv_where
                    ,po_message_severity  =>  lv_severity
                    ,po_message_tab       =>  lt_messages);
        --
    END IF;  
    --
    IF lv_severity = awlrs_util.c_msg_cat_success
      THEN
        --
        lt_messages.DELETE;
        --
           update_qry_attributes(pi_old_qry_attrib_id     =>  pi_old_qry_attrib_id
                                ,pi_old_query_id          =>  pi_old_query_id
                                ,pi_old_inv_type          =>  pi_old_inv_type
                                ,pi_old_pre_bracket       =>  pi_old_pre_bracket
                                ,pi_old_operator          =>  pi_old_operator
                                ,pi_old_attribute_name    =>  pi_old_attribute_name
                                ,pi_old_condition         =>  pi_old_condition
                                ,pi_old_attribute_value   =>  pi_old_attribute_value
                                ,pi_old_post_bracket      =>  pi_old_post_bracket
                                ,pi_new_inv_type          =>  pi_new_inv_type
                                ,pi_new_pre_bracket       =>  pi_new_pre_bracket
                                ,pi_new_operator          =>  pi_new_operator
                                ,pi_new_attribute_name    =>  pi_new_attribute_name
                                ,pi_new_condition         =>  pi_new_condition
                                ,pi_new_attribute_value   =>  pi_new_attribute_value
                                ,pi_new_post_bracket      =>  pi_new_post_bracket
                                ,po_message_severity      =>  lv_severity
                                ,po_message_tab           =>  lt_messages);
        --    
    END IF;  
    --
    IF lt_messages.COUNT > 0
     THEN
        awlrs_util.get_message_cursor(pi_message_tab => lt_messages
                                     ,po_cursor      => po_message_cursor);
        awlrs_util.get_highest_severity(pi_message_tab      => lt_messages
                                       ,po_message_severity => po_message_severity);
    ELSE
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
    END IF;
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_query_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END update_query_and_attribs;                                                                            
  --
  -----------------------------------------------------------------------------
  --
  
  PROCEDURE create_scheduled_alert(pi_inv_type             IN     hig_alert_types.halt_nit_inv_type%TYPE
                                  ,pi_query_id             IN     hig_alert_types.halt_hqt_id%TYPE
                                  ,pi_descr                IN     hig_alert_types.halt_description%TYPE 
                                  ,pi_frequency_id         IN     hig_alert_types.halt_frequency_id%TYPE
                                  ,pi_suspend_query        IN     hig_alert_types.halt_suspend_query%TYPE
                                  ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor          OUT sys_refcursor) 
  IS
  --
  BEGIN
    --
    SAVEPOINT create_sched_alert_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Inv Type'
                               ,pi_parameter_value => pi_inv_type);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Frequency Id'
                               ,pi_parameter_value => pi_frequency_id);
    --
    awlrs_util.validate_yn(pi_parameter_desc  => 'Suspended'
                          ,pi_parameter_value => pi_suspend_query);
    --
    /*
    ||insert into hig_alert_types.
    */
    INSERT
      INTO hig_alert_types
          (halt_id
          ,halt_alert_type
          ,halt_nit_inv_type
          ,halt_hqt_id
          ,halt_description
          ,halt_immediate
          ,halt_frequency_id
          ,halt_suspend_query
          ,halt_next_run_date
          )
    VALUES (halt_id_seq.NEXTVAL
           ,'Q'
           ,pi_inv_type 
           ,pi_query_id
           ,pi_descr
           ,'N'
           ,pi_frequency_id
           ,pi_suspend_query
           ,hig_alert.get_next_run_date(pi_hsfr_id => pi_frequency_id)
           );
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_sched_alert_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_scheduled_alert;                                                                 
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_scheduled_alert(pi_old_alert_id        IN     hig_alert_types.halt_id%TYPE
                                  ,pi_old_query_id        IN     hig_alert_types.halt_hqt_id%TYPE
                                  ,pi_old_inv_type        IN     hig_alert_types.halt_nit_inv_type%TYPE
                                  ,pi_old_descr           IN     hig_alert_types.halt_description%TYPE
                                  ,pi_old_frequency_id    IN     hig_alert_types.halt_frequency_id%TYPE
                                  ,pi_old_suspend_query   IN     hig_alert_types.halt_suspend_query%TYPE
                                  ,pi_new_descr           IN     hig_alert_types.halt_description%TYPE        
                                  ,pi_new_frequency_id    IN     hig_alert_types.halt_frequency_id%TYPE                    
                                  ,po_message_severity       OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor         OUT sys_refcursor)
  IS
    --
    lr_db_rec        hig_alert_types%ROWTYPE;
    lv_upd           varchar2(1) := 'N';
    lv_error_text    varchar2(32767);
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM hig_alert_types
       WHERE halt_id = pi_old_alert_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Alert Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_sched_alert_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.halt_id != pi_old_alert_id
     OR (lr_db_rec.halt_id IS NULL AND pi_old_alert_id IS NOT NULL)
     OR (lr_db_rec.halt_id IS NOT NULL AND pi_old_alert_id IS NULL)
     --
     OR (lr_db_rec.halt_hqt_id != pi_old_query_id)
     OR (lr_db_rec.halt_hqt_id IS NULL AND pi_old_query_id IS NOT NULL)
     OR (lr_db_rec.halt_hqt_id IS NOT NULL AND pi_old_query_id IS NULL)
     --
     OR (lr_db_rec.halt_nit_inv_type != pi_old_inv_type)
     OR (lr_db_rec.halt_nit_inv_type IS NULL AND pi_old_inv_type IS NOT NULL)
     OR (lr_db_rec.halt_nit_inv_type IS NOT NULL AND pi_old_inv_type IS NULL)
     --
     OR (UPPER(lr_db_rec.halt_description) != UPPER(pi_old_descr))
     OR (UPPER(lr_db_rec.halt_description) IS NULL AND UPPER(pi_old_descr) IS NOT NULL)
     OR (UPPER(lr_db_rec.halt_description) IS NOT NULL AND UPPER(pi_old_descr) IS NULL)
     --
     OR (lr_db_rec.halt_frequency_id != pi_old_frequency_id)
     OR (lr_db_rec.halt_frequency_id IS NULL AND pi_old_frequency_id IS NOT NULL)
     OR (lr_db_rec.halt_frequency_id IS NOT NULL AND pi_old_frequency_id IS NULL)
     --
     OR (lr_db_rec.halt_suspend_query != pi_old_suspend_query)
     OR (lr_db_rec.halt_suspend_query IS NULL AND pi_old_suspend_query IS NOT NULL)
     OR (lr_db_rec.halt_suspend_query IS NOT NULL AND pi_old_suspend_query IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF UPPER(pi_old_descr) != UPPER(pi_new_descr)
       OR (UPPER(pi_old_descr) IS NULL AND UPPER(pi_new_descr) IS NOT NULL)
       OR (UPPER(pi_old_descr) IS NOT NULL AND UPPER(pi_new_descr) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF pi_old_frequency_id != pi_new_frequency_id
       OR (pi_old_frequency_id IS NULL AND pi_new_frequency_id IS NOT NULL)
       OR (pi_old_frequency_id IS NOT NULL AND pi_new_frequency_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE hig_alert_types
           SET halt_description   = pi_new_descr
              ,halt_frequency_id  = pi_new_frequency_id
         WHERE halt_id            = pi_old_alert_id;          
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF; 
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_sched_alert_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_scheduled_alert;                                  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_scheduled_alert(pi_alert_id              IN     hig_alert_types.halt_id%TYPE
                                  ,po_message_severity         OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor           OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    SAVEPOINT delete_sched_alert_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    IF NOT alert_exists(pi_halt_id => pi_alert_id)
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Alert Id:  '||pi_alert_id);
    END IF;
    /*
    ||delete from hig_alert_type_mail.
    */
    DELETE 
      FROM hig_alert_type_mail
     WHERE hatm_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_type_recipients.
    */
    DELETE 
      FROM hig_alert_type_recipients
     WHERE hatr_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_recipients.
    */
    DELETE 
      FROM hig_alert_recipients
     WHERE har_hal_id in (SELECT hal_id
                           FROM hig_alerts
                          WHERE hal_halt_id = pi_alert_id);
    
    /*
    ||delete from hig_alerts.
    */
    DELETE 
      FROM hig_alerts
     WHERE hal_halt_id = pi_alert_id;
    --
    /*
    ||delete from hig_alert_types.
    */
    DELETE 
      FROM hig_alert_types
     WHERE halt_id = pi_alert_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_sched_alert_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_scheduled_alert;                                            
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_trigger(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                          ,po_message_severity        OUT hig_codes.hco_code%TYPE
                          ,po_message_cursor          OUT sys_refcursor)
  IS
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    IF NOT recipient_exists(pi_hatr_halt_id => pi_alert_id)
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 523
                     ,pi_supplementary_info  => 'Email Recipients are not setup for this alert');
    END IF;
    --
    IF NOT mail_exists(pi_hatm_halt_id => pi_alert_id)
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 523
                     ,pi_supplementary_info  => 'Email is not setup for this alert');
    END IF;
    --
    IF NOT hig_alert.create_trigger(pi_halt_id    => pi_alert_id
                                   ,po_error_text => lv_error_text)
      THEN
        --
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 523
                     ,pi_supplementary_info => lv_error_text);                                        
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_trigger;    
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE drop_trigger(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                        ,pi_trigger_name         IN     hig_alert_types.halt_trigger_name%TYPE
                        ,po_message_severity        OUT hig_codes.hco_code%TYPE
                        ,po_message_cursor          OUT sys_refcursor)
  IS                      
  --
  lv_error_text varchar2(32767);
  --
  BEGIN
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Trigger Name'
                               ,pi_parameter_value => pi_trigger_name);
    --
    IF NOT hig_alert.drop_trigger(pi_halt_id       => pi_alert_id
                                 ,pi_trigger_name  => pi_trigger_name
                                 ,po_error_text    => lv_error_text)
      THEN
        --
        hig.raise_ner(pi_appl               => 'HIG'
                     ,pi_id                 => 544
                     ,pi_supplementary_info => lv_error_text);                                        
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END drop_trigger;             
   
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE suspend_query(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                         ,po_next_run_date           OUT hig_alert_types.halt_next_run_date%TYPE
                         ,po_message_severity        OUT hig_codes.hco_code%TYPE
                         ,po_message_cursor          OUT sys_refcursor)
  IS                      
  --
  BEGIN
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    UPDATE hig_alert_types
       SET halt_next_run_date = null
          ,halt_suspend_query = 'Y'
     WHERE halt_id            = pi_alert_id; 
    --
    po_next_run_date := null; 
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END suspend_query;

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE resume_query(pi_alert_id             IN     hig_alert_types.halt_id%TYPE
                        ,pi_frequency_id         IN     hig_alert_types.halt_frequency_id%TYPE
                        ,po_next_run_date           OUT hig_alert_types.halt_next_run_date%TYPE
                        ,po_message_severity        OUT hig_codes.hco_code%TYPE
                        ,po_message_cursor          OUT sys_refcursor)
  IS                      
  --
  lv_next_run_date hig_alert_types.halt_next_run_date%TYPE;
  --
  BEGIN
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Alert Id'
                               ,pi_parameter_value => pi_alert_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Frequency Id'
                               ,pi_parameter_value => pi_frequency_id);
    --
    lv_next_run_date := hig_alert.get_next_run_date(pi_hsfr_id => pi_frequency_id);
    --
    UPDATE hig_alert_types
       SET halt_next_run_date = lv_next_run_date
          ,halt_suspend_query = 'N'
     WHERE halt_id            = pi_alert_id;
    -- 
    po_next_run_date := lv_next_run_date; 
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END resume_query;                                                              
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_logs(po_message_severity        OUT hig_codes.hco_code%TYPE
                          ,po_message_cursor          OUT sys_refcursor
                          ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT haml_halt_id           alert_id
          ,haml_hal_id            alert_log_id  
          ,haml_har_id            recip_id
          ,haml_nit_inv_type      inv_type
          ,haml_descr             inv_type_descr
          ,haml_description       alert_descr
          ,haml_pk_column         primary_key
          ,haml_pk_id             pk_id
          ,haml_recipient_email   recip_email
          ,haml_created_date      alert_raised_date
          ,haml_email_date_sent   alert_sent_date
          ,haml_status            status
          ,haml_mail_from         mail_from
          ,haml_subject           mail_subject
          ,haml_email_body        mail_text
          ,haml_comments          failure_comments
      FROM hig_alert_manager_logs_vw;    
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_alert_logs;                          

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_alert_log(pi_alert_log_id         IN     hig_alert_manager_logs_vw.haml_hal_id%TYPE
                         ,po_message_severity        OUT hig_codes.hco_code%TYPE
                         ,po_message_cursor          OUT sys_refcursor
                         ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT haml_halt_id           alert_id
          ,haml_hal_id            alert_log_id  
          ,haml_har_id            recip_id
          ,haml_nit_inv_type      inv_type
          ,haml_descr             inv_type_descr
          ,haml_description       alert_descr
          ,haml_pk_column         primary_key
          ,haml_pk_id             pk_id
          ,haml_recipient_email   recip_email
          ,haml_created_date      alert_raised_date
          ,haml_email_date_sent   alert_sent_date
          ,haml_status            status
          ,haml_mail_from         mail_from
          ,haml_subject           mail_subject
          ,haml_email_body        mail_text
          ,haml_comments          failure_comments
      FROM hig_alert_manager_logs_vw
     WHERE haml_halt_id = pi_alert_log_id;    
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_alert_log;                                                     

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_alert_logs(pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                ,pi_skip_n_rows          IN     PLS_INTEGER
                                ,pi_pagesize             IN     PLS_INTEGER
                                ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor          OUT sys_refcursor
                                ,po_cursor                  OUT sys_refcursor)
    IS
    --
    lv_order_by         nm3type.max_varchar2;
    lv_filter           nm3type.max_varchar2;
    --
    lv_cursor_sql  nm3type.max_varchar2 :='SELECT haml_halt_id         alert_id'
                                              ||',haml_hal_id          alert_log_id'
                                              ||',haml_har_id          recip_id'
                                              ||',haml_nit_inv_type    inv_type'
                                              ||',haml_descr           inv_type_descr'
                                              ||',haml_description     alert_descr'
                                              ||',haml_pk_column       primary_key'
                                              ||',haml_pk_id           pk_id'
                                              ||',haml_recipient_email recip_email'
                                              ||',haml_created_date    alert_raised_date'
                                              ||',haml_email_date_sent alert_sent_date'
                                              ||',haml_status          status'
                                              ||',haml_mail_from       mail_from'
                                              ||',haml_subject         mail_subject'
                                              ||',haml_email_body      mail_text'
                                              ||',haml_comments        failure_comments'
                                              ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                         ||' FROM hig_alert_manager_logs_vw'
    ;
    --
    lt_column_data  awlrs_util.column_data_tab;
    --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'inv_type'
                                ,pi_query_col    => 'haml_descr'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'inv_type_descr'
                                ,pi_query_col    => 'halt_alert_type'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_descr'
                                ,pi_query_col    => 'haml_description'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'primary_key'
                                ,pi_query_col    => 'haml_pk_column'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'pk_id'
                                ,pi_query_col    => 'haml_pk_id'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'recip_email'
                                ,pi_query_col    => 'haml_recipient_email'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_raised_date'
                                ,pi_query_col    => 'haml_created_date'
                                ,pi_datatype     => awlrs_util.c_datetime_col
                                ,pi_mask         => 'DD-MON-YYYY HH24:MI:SS'
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'alert_sent_date'
                                ,pi_query_col    => 'haml_email_date_sent'
                                ,pi_datatype     => awlrs_util.c_datetime_col
                                ,pi_mask         => 'DD-MON-YYYY HH24:MI:SS'
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'status'
                                ,pi_query_col    => 'haml_status'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'WHERE' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'haml_hal_id')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_alert_logs;
                                                      
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE send_email(pi_recip_ids             IN     nm3type.tab_number
                      ,po_message_severity         OUT hig_codes.hco_code%TYPE
                      ,po_message_cursor           OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    FOR i IN 1..pi_recip_ids.COUNT LOOP
    --
      hig_alert.send_mail(pi_har_id      => pi_recip_ids(i)
                         ,pi_from_screen => 'Y');    --when set to Y, commits
    END LOOP;                     
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END send_email;                      
 
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_groups(po_message_severity        OUT hig_codes.hco_code%TYPE
                           ,po_message_cursor          OUT sys_refcursor
                           ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmg_id        nmg_id  
          ,nmg_name      nmg_name  
      FROM nm_mail_groups    
    ORDER BY UPPER(nmg_name);
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_groups;                           

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_group(pi_nmg_id               IN     nm_mail_groups.nmg_id%TYPE
                          ,po_message_severity        OUT hig_codes.hco_code%TYPE
                          ,po_message_cursor          OUT sys_refcursor
                          ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmg_id        nmg_id  
          ,nmg_name      nmg_name  
      FROM nm_mail_groups
     WHERE nmg_id = pi_nmg_id;     
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_group;                                                        

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_mail_groups(pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                 ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                 ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                 ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                 ,pi_skip_n_rows          IN     PLS_INTEGER
                                 ,pi_pagesize             IN     PLS_INTEGER
                                 ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                 ,po_message_cursor          OUT sys_refcursor
                                 ,po_cursor                  OUT sys_refcursor)
    IS
    --
    lv_order_by         nm3type.max_varchar2;
    lv_filter           nm3type.max_varchar2;
    --
    lv_cursor_sql  nm3type.max_varchar2 :='SELECT nmg_id   nmg_id'
                                              ||',nmg_name nmg_name'
                                              ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                         ||' FROM nm_mail_groups'
    ;
    --
    lt_column_data  awlrs_util.column_data_tab;
    --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmg_id'
                                ,pi_query_col    => 'nmg_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmg_name'
                                ,pi_query_col    => 'nmg_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'WHERE' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'UPPER(nmg_name)')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_mail_groups;                                                                                    
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION mail_group_exists(pi_nmg_name   IN     nm_mail_groups.nmg_name%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM nm_mail_groups
     WHERE nmg_name = UPPER(pi_nmg_name);
    -- 
    RETURN (lv_cnt > 0);  
    --
 END mail_group_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION mail_group_exists(pi_nmg_id      IN     nm_mail_groups.nmg_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM nm_mail_groups
     WHERE nmg_id = pi_nmg_id;
    -- 
    RETURN (lv_cnt > 0);  
    --
  END mail_group_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION mail_id_exists(pi_nmu_id  IN  nm_mail_users.nmu_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM nm_mail_users
     WHERE nmu_id = pi_nmu_id;
    -- 
    RETURN (lv_cnt > 0);  
    --
  END mail_id_exists;

  --
  -----------------------------------------------------------------------------
  --
  FUNCTION name_exists(pi_nmu_name  IN  nm_mail_users.nmu_name%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM nm_mail_users
     WHERE UPPER(nmu_name) = UPPER(pi_nmu_name);
    -- 
    RETURN (lv_cnt > 0);  
    --
  END name_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION email_exists(pi_nmu_email  IN  nm_mail_users.nmu_email_address%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM nm_mail_users
     WHERE UPPER(nmu_email_address) = UPPER(pi_nmu_email);
    -- 
    RETURN (lv_cnt > 0);  
    --
  END email_exists;

  --
  -----------------------------------------------------------------------------
  --
  FUNCTION user_id_exists(pi_nmu_hus_user_id  IN  nm_mail_users.nmu_hus_user_id%TYPE)
    RETURN BOOLEAN
  IS
     lv_cnt    number;
  BEGIN
    --
    SELECT COUNT(*) 
      INTO lv_cnt
      FROM nm_mail_users
     WHERE nmu_hus_user_id = pi_nmu_hus_user_id;
     
    RETURN (lv_cnt > 0);  
    --   
  END user_id_exists;
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_mail_group(pi_nmg_name                 IN     nm_mail_groups.nmg_name%TYPE
                             ,po_message_severity            OUT hig_codes.hco_code%TYPE
                             ,po_message_cursor              OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT create_mail_grp_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Group Name'
                               ,pi_parameter_value => pi_nmg_name);
    --
    IF mail_group_exists(pi_nmg_name => pi_nmg_name) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'Group Name:  '||pi_nmg_name);
    END IF;
    --
    /*
    ||insert into nm_mail_groups.
    */
    INSERT
      INTO nm_mail_groups
          (nmg_id
          ,nmg_name
          )
    VALUES (nmg_id_seq.NEXTVAL
           ,pi_nmg_name
           );
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_mail_grp_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_mail_group;                             
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_mail_group(pi_old_nmg_id               IN     nm_mail_groups.nmg_id%TYPE
                             ,pi_old_nmg_name             IN     nm_mail_groups.nmg_name%TYPE
                             ,pi_new_nmg_id               IN     nm_mail_groups.nmg_id%TYPE
                             ,pi_new_nmg_name             IN     nm_mail_groups.nmg_name%TYPE
                             ,po_message_severity            OUT hig_codes.hco_code%TYPE
                             ,po_message_cursor              OUT sys_refcursor)
  IS
    --
    lr_db_rec        nm_mail_groups%ROWTYPE;
    lv_upd           VARCHAR2(1) := 'N';
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM nm_mail_groups
       WHERE nmg_id = pi_old_nmg_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Group Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_mail_group_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Group Id'
                               ,pi_parameter_value => pi_new_nmg_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Group Name'
                               ,pi_parameter_value => pi_new_nmg_name);
    --
    IF mail_group_exists(pi_nmg_name => pi_new_nmg_name) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'Group Name:  '||pi_new_nmg_name);
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.nmg_id != pi_old_nmg_id
     OR (lr_db_rec.nmg_id IS NULL AND pi_old_nmg_id IS NOT NULL)
     OR (lr_db_rec.nmg_id IS NOT NULL AND pi_old_nmg_id IS NULL)
     --
     OR (UPPER(lr_db_rec.nmg_name) != UPPER(pi_old_nmg_name))
     OR (UPPER(lr_db_rec.nmg_name) IS NULL AND UPPER(pi_old_nmg_name) IS NOT NULL)
     OR (UPPER(lr_db_rec.nmg_name) IS NOT NULL AND UPPER(pi_old_nmg_name) IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF UPPER(pi_old_nmg_name) != UPPER(pi_new_nmg_name)
       OR (UPPER(pi_old_nmg_name) IS NULL AND UPPER(pi_new_nmg_name) IS NOT NULL)
       OR (UPPER(pi_old_nmg_name) IS NOT NULL AND UPPER(pi_new_nmg_name) IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE nm_mail_groups
           SET nmg_name        = UPPER(pi_new_nmg_name)
         WHERE nmg_id          = pi_old_nmg_id;
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF;
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_mail_group_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_mail_group;                                                     

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_mail_group(pi_nmg_id                   IN     nm_mail_groups.nmg_id%TYPE
                             ,po_message_severity            OUT hig_codes.hco_code%TYPE
                             ,po_message_cursor              OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT delete_mail_grp_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Group Id'
                               ,pi_parameter_value => pi_nmg_id);
    --
    IF NOT mail_group_exists(pi_nmg_id => pi_nmg_id) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Group Id:  '||pi_nmg_id);
    END IF;
    --
    /*
    ||delete from nm_mail_groups.
    */
    DELETE 
      FROM nm_mail_groups
     WHERE nmg_id = pi_nmg_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_mail_grp_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_mail_group;                             
                             
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_grp_members(pi_nmg_id               IN     nm_mail_groups.nmg_id%TYPE
                                ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor          OUT sys_refcursor
                                ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmgm_nmg_id      nmgm_nmg_id  
          ,nmgm_nmu_id      nmgm_nmu_id
          ,nmu_name         nmu_name  
      FROM v_nm_mail_group_membership
     WHERE nmgm_nmg_id = pi_nmg_id   
    ORDER BY UPPER(nmu_name);
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_grp_members;                                 

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_grp_member(pi_nmg_id               IN     nm_mail_groups.nmg_id%TYPE
                               ,pi_nmgm_nmu_id          IN     nm_mail_group_membership.nmgm_nmu_id%TYPE
                               ,po_message_severity        OUT hig_codes.hco_code%TYPE
                               ,po_message_cursor          OUT sys_refcursor
                               ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmgm_nmg_id      nmgm_nmg_id  
          ,nmgm_nmu_id      nmgm_nmu_id
          ,nmu_name         nmu_name  
      FROM v_nm_mail_group_membership
     WHERE nmgm_nmg_id = pi_nmg_id 
       AND nmgm_nmu_id = pi_nmgm_nmu_id;  
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_grp_member;                                                            

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_mail_grp_members(pi_nmg_id               IN     nm_mail_groups.nmg_id%TYPE
                                      ,pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                      ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                      ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                      ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                      ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                      ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                      ,pi_skip_n_rows          IN     PLS_INTEGER
                                      ,pi_pagesize             IN     PLS_INTEGER
                                      ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                      ,po_message_cursor          OUT sys_refcursor
                                      ,po_cursor                  OUT sys_refcursor)
    IS
    --
    lv_order_by         nm3type.max_varchar2;
    lv_filter           nm3type.max_varchar2;
    --
    lv_cursor_sql  nm3type.max_varchar2 :='SELECT nmgm_nmg_id nmgm_nmg_id'
                                              ||',nmgm_nmu_id nmgm_nmu_id'
                                              ||',nmu_name    nmu_name'
                                              ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                         ||' FROM v_nm_mail_group_membership'
                                        ||' WHERE nmgm_nmg_id = :pi_nmg_id'
    ;
    --
    lt_column_data  awlrs_util.column_data_tab;
    --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmgm_nmg_id'
                                ,pi_query_col    => 'nmgm_nmg_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmgm_nmu_id'
                                ,pi_query_col    => 'nmgm_nmu_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmu_name'
                                ,pi_query_col    => 'nmu_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'UPPER(nmu_name)')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql
    USING pi_nmg_id
    ;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);

  END get_paged_mail_grp_members;                                                                                    
  
  --
  -----------------------------------------------------------------------------
  --
  FUNCTION group_member_exists(pi_nmgm_nmg_id   IN   nm_mail_group_membership.nmgm_nmg_id%TYPE
                              ,pi_nmgm_nmu_id   IN   nm_mail_group_membership.nmgm_nmu_id%TYPE)
    RETURN VARCHAR2
  IS
    lv_exists VARCHAR2(1):= 'N';
  BEGIN
    --
    IF pi_nmgm_nmg_id IS NOT NULL
      THEN
        SELECT 'Y'
          INTO lv_exists
          FROM nm_mail_group_membership
         WHERE nmgm_nmg_id = pi_nmgm_nmg_id
           AND nmgm_nmu_id = pi_nmgm_nmu_id;
    ELSE
      lv_exists := 'Y';   
    END IF;     
    --
    RETURN lv_exists;
    --
  EXCEPTION
    WHEN NO_DATA_FOUND
     THEN
        RETURN lv_exists;
  END group_member_exists;

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_grp_members_lov(po_message_severity    OUT  hig_codes.hco_code%TYPE
                               ,po_message_cursor      OUT  sys_refcursor
                               ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmu_id
          ,nmu_name 
      FROM nm_mail_users 
    ORDER BY UPPER(nmu_name);
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_grp_members_lov;                                

  --
  -----------------------------------------------------------------------------
  --     
  PROCEDURE create_mail_grp_member(pi_nmgm_nmg_id              IN     nm_mail_group_membership.nmgm_nmg_id%TYPE
                                  ,pi_nmgm_nmu_id              IN     nm_mail_group_membership.nmgm_nmu_id%TYPE
                                  ,po_message_severity            OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor              OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT create_group_member_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Group Id'
                               ,pi_parameter_value => pi_nmgm_nmg_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'User Id'
                               ,pi_parameter_value => pi_nmgm_nmu_id);
    --
    IF group_member_exists(pi_nmgm_nmg_id => pi_nmgm_nmg_id
                          ,pi_nmgm_nmu_id => pi_nmgm_nmu_id) = 'Y'
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'User Id:  '||pi_nmgm_nmu_id);
    END IF;
    --
    /*
    ||insert into nm_mail_group_membership.
    */
    INSERT
      INTO nm_mail_group_membership
          (nmgm_nmg_id
          ,nmgm_nmu_id
          )
    VALUES (pi_nmgm_nmg_id
           ,pi_nmgm_nmu_id
           );
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_group_member_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_mail_grp_member;                                  
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_mail_grp_member(pi_old_nmgm_nmg_id          IN     nm_mail_group_membership.nmgm_nmg_id%TYPE
                                  ,pi_old_nmgm_nmu_id          IN     nm_mail_group_membership.nmgm_nmu_id%TYPE
                                  ,pi_new_nmgm_nmg_id          IN     nm_mail_group_membership.nmgm_nmg_id%TYPE
                                  ,pi_new_nmgm_nmu_id          IN     nm_mail_group_membership.nmgm_nmu_id%TYPE
                                  ,po_message_severity            OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor              OUT sys_refcursor)
  IS
    --
    lr_db_rec        nm_mail_group_membership%ROWTYPE;
    lv_upd           VARCHAR2(1) := 'N';
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM nm_mail_group_membership
       WHERE nmgm_nmg_id = pi_old_nmgm_nmg_id
         AND nmgm_nmu_id = pi_old_nmgm_nmu_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Group User Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_grp_member_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Group Id'
                               ,pi_parameter_value => pi_new_nmgm_nmg_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'User Id'
                               ,pi_parameter_value => pi_new_nmgm_nmu_id);
    --
    IF group_member_exists(pi_nmgm_nmg_id => pi_new_nmgm_nmg_id
                          ,pi_nmgm_nmu_id => pi_new_nmgm_nmu_id) = 'Y'
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'Group User Id:  '||pi_new_nmgm_nmu_id);
    END IF;
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.nmgm_nmg_id != pi_old_nmgm_nmg_id
     OR (lr_db_rec.nmgm_nmg_id IS NULL AND pi_old_nmgm_nmg_id IS NOT NULL)
     OR (lr_db_rec.nmgm_nmg_id IS NOT NULL AND pi_old_nmgm_nmg_id IS NULL)
     --
     OR (UPPER(lr_db_rec.nmgm_nmu_id) != pi_old_nmgm_nmu_id)
     OR (UPPER(lr_db_rec.nmgm_nmu_id) IS NULL AND pi_old_nmgm_nmu_id IS NOT NULL)
     OR (UPPER(lr_db_rec.nmgm_nmu_id) IS NOT NULL AND pi_old_nmgm_nmu_id IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF pi_old_nmgm_nmg_id != pi_new_nmgm_nmg_id
       OR (pi_old_nmgm_nmg_id IS NULL AND pi_new_nmgm_nmg_id IS NOT NULL)
       OR (pi_old_nmgm_nmg_id IS NOT NULL AND pi_new_nmgm_nmg_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF UPPER(pi_old_nmgm_nmu_id) != pi_new_nmgm_nmu_id
       OR (UPPER(pi_old_nmgm_nmu_id) IS NULL AND pi_new_nmgm_nmu_id IS NOT NULL)
       OR (UPPER(pi_old_nmgm_nmu_id) IS NOT NULL AND pi_new_nmgm_nmu_id IS NULL)
       THEN
         lv_upd := 'Y';
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE nm_mail_group_membership
           SET nmgm_nmg_id     = pi_new_nmgm_nmg_id
              ,nmgm_nmu_id     = pi_new_nmgm_nmu_id
         WHERE nmgm_nmg_id     = pi_old_nmgm_nmg_id
           AND nmgm_nmu_id     = pi_old_nmgm_nmu_id;
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF;
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_grp_member_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_mail_grp_member;                                                     

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_mail_grp_member(pi_nmgm_nmg_id              IN     nm_mail_group_membership.nmgm_nmg_id%TYPE
                                  ,pi_nmgm_nmu_id              IN     nm_mail_group_membership.nmgm_nmu_id%TYPE
                                  ,po_message_severity            OUT hig_codes.hco_code%TYPE
                                  ,po_message_cursor              OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT delete_grp_member_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Group Id'
                               ,pi_parameter_value => pi_nmgm_nmg_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'User Id'
                               ,pi_parameter_value => pi_nmgm_nmu_id);
    --
    IF group_member_exists(pi_nmgm_nmg_id => pi_nmgm_nmg_id
                          ,pi_nmgm_nmu_id => pi_nmgm_nmu_id) <>'Y'
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'User Id:  '||pi_nmgm_nmu_id);
    END IF;
    --
    /*
    ||delete from nm_mail_group_membership.
    */
    DELETE 
      FROM nm_mail_group_membership
     WHERE nmgm_nmg_id = pi_nmgm_nmg_id
       AND nmgm_nmu_id = pi_nmgm_nmu_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_grp_member_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_mail_grp_member;                                   
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_users(po_message_severity       OUT hig_codes.hco_code%TYPE
                          ,po_message_cursor         OUT sys_refcursor
                          ,po_cursor                 OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmu_id             nmu_id
          ,nmu_name           nmu_name
          ,nmu_email_address  nmu_email_address
          ,nmu_hus_user_id    nmu_hus_user_id
          ,hus_name           hus_name
      FROM nm_mail_users
          ,hig_users
     WHERE nmu_hus_user_id = hus_user_id(+)    
    ORDER BY UPPER(nmu_name);
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_users;                            

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_mail_user(pi_nmu_id               IN     nm_mail_users.nmu_id%TYPE
                         ,po_message_severity        OUT hig_codes.hco_code%TYPE
                         ,po_message_cursor          OUT sys_refcursor
                         ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmu_id             nmu_id
          ,nmu_name           nmu_name
          ,nmu_email_address  nmu_email_address
          ,nmu_hus_user_id    nmu_hus_user_id
          ,hus_name           hus_name
      FROM nm_mail_users
          ,hig_users 
     WHERE nmu_id          = pi_nmu_id
       AND nmu_hus_user_id = hus_user_id(+);     
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_mail_user;                                                     

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_paged_mail_users(pi_filter_columns       IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                ,pi_filter_operators     IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                ,pi_filter_values_1      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                ,pi_filter_values_2      IN     nm3type.tab_varchar32767 DEFAULT CAST(NULL AS nm3type.tab_varchar32767)
                                ,pi_order_columns        IN     nm3type.tab_varchar30 DEFAULT CAST(NULL AS nm3type.tab_varchar30)
                                ,pi_order_asc_desc       IN     nm3type.tab_varchar4 DEFAULT CAST(NULL AS nm3type.tab_varchar4)
                                ,pi_skip_n_rows          IN     PLS_INTEGER
                                ,pi_pagesize             IN     PLS_INTEGER
                                ,po_message_severity        OUT hig_codes.hco_code%TYPE
                                ,po_message_cursor          OUT sys_refcursor
                                ,po_cursor                  OUT sys_refcursor)
  IS
      --
      lv_order_by         nm3type.max_varchar2;
      lv_filter           nm3type.max_varchar2;
      --
      lv_cursor_sql  nm3type.max_varchar2 :='SELECT nmu_id            nmu_id'
                                                ||',nmu_name          nmu_name'
                                                ||',nmu_email_address nmu_email_address'
                                                ||',nmu_hus_user_id   nmu_hus_user_id'
                                                ||',hus_name          hus_name'
                                                ||',COUNT(1) OVER(ORDER BY 1 RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) row_count'
                                           ||' FROM nm_mail_users'
                                                ||',hig_users'
                                          ||' WHERE nmu_hus_user_id = hus_user_id(+)';
      --
      lt_column_data  awlrs_util.column_data_tab;
      --
    PROCEDURE set_column_data(po_column_data IN OUT awlrs_util.column_data_tab)
      IS
    BEGIN
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmu_id'
                                ,pi_query_col    => 'nmu_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmu_name'
                                ,pi_query_col    => 'nmu_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmu_email_address'
                                ,pi_query_col    => 'nmu_email_address'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'nmu_hus_user_id'
                                ,pi_query_col    => 'nmu_hus_user_id'
                                ,pi_datatype     => awlrs_util.c_number_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
      awlrs_util.add_column_data(pi_cursor_col   => 'hus_name'
                                ,pi_query_col    => 'hus_name'
                                ,pi_datatype     => awlrs_util.c_varchar2_col
                                ,pi_mask         => NULL
                                ,pio_column_data => po_column_data);
      --
    END set_column_data;
    --
  BEGIN
    /*
    ||Get the Order By clause.
    */
    lv_order_by := awlrs_util.gen_order_by(pi_order_columns  => pi_order_columns
                                          ,pi_order_asc_desc => pi_order_asc_desc);
    /*
    ||Process the filter.
    */
    IF pi_filter_columns.COUNT > 0
     THEN
        --
        set_column_data(po_column_data => lt_column_data);
        --
        awlrs_util.process_filter(pi_columns      => pi_filter_columns
                                 ,pi_column_data  => lt_column_data
                                 ,pi_operators    => pi_filter_operators
                                 ,pi_values_1     => pi_filter_values_1
                                 ,pi_values_2     => pi_filter_values_2
                                 ,pi_where_or_and => 'AND' --Depends on lv_driving_sql if it has a where clause already then AND otherwise WHERE
                                 ,po_where_clause => lv_filter);
        --
    END IF;
    --
    lv_cursor_sql := lv_cursor_sql
                     ||lv_filter
                     ||' ORDER BY '||NVL(lv_order_by,'UPPER(nmu_name)')
                     ||' OFFSET '||pi_skip_n_rows||' ROWS '
    ;
    --
    IF pi_pagesize IS NOT NULL
      THEN
        lv_cursor_sql := lv_cursor_sql||' FETCH NEXT '||pi_pagesize||' ROWS ONLY ';
    END IF;
    --
    OPEN po_cursor FOR lv_cursor_sql;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_paged_mail_users;        
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_user_mail_grps(pi_nmgm_nmu_id          IN     nm_mail_group_membership.nmgm_nmu_id%TYPE
                              ,po_message_severity        OUT hig_codes.hco_code%TYPE
                              ,po_message_cursor          OUT sys_refcursor
                              ,po_cursor                  OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT nmgm_nmg_id      nmgm_nmg_id  
          ,nmg_name         nmg_name  
      FROM v_nm_mail_group_membership
     WHERE nmgm_nmu_id = pi_nmgm_nmu_id;  
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END get_user_mail_grps; 
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE get_users_lov(po_message_severity    OUT  hig_codes.hco_code%TYPE
                         ,po_message_cursor      OUT  sys_refcursor
                         ,po_cursor              OUT  sys_refcursor)
  IS
  --
  BEGIN
    --
    OPEN po_cursor FOR
    SELECT hus_user_id
          ,hus_name 
      FROM hig_users 
    ORDER BY UPPER(hus_name);
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END get_users_lov;                                                                                   
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE create_mail_user(pi_nmu_name                 IN     nm_mail_users.nmu_name%TYPE
                            ,pi_nmu_email                IN     nm_mail_users.nmu_email_address%TYPE
                            ,pi_nmu_user_id              IN     nm_mail_users.nmu_hus_user_id%TYPE
                            ,po_message_severity            OUT hig_codes.hco_code%TYPE
                            ,po_message_cursor              OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT create_mail_user_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Name'
                               ,pi_parameter_value => pi_nmu_name);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Email'
                               ,pi_parameter_value => pi_nmu_email);
    --
    IF name_exists(pi_nmu_name => pi_nmu_name) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'Name:  '||pi_nmu_name);
    END IF;
    --
    IF email_exists(pi_nmu_email => pi_nmu_email) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 64
                     ,pi_supplementary_info  => 'Email:  '||pi_nmu_email);
    END IF;
    --
    IF user_id_exists(pi_nmu_hus_user_id => pi_nmu_user_id) 
          THEN
            hig.raise_ner(pi_appl => 'HIG'
                         ,pi_id   => 64
                         ,pi_supplementary_info  => 'User Id:  '||pi_nmu_user_id);
    END IF;
    --                     
    /*
    ||insert into nm_mail_users.
    */
    INSERT
      INTO nm_mail_users
          (nmu_id
          ,nmu_name
          ,nmu_email_address
          ,nmu_hus_user_id
          )
    VALUES (nmu_id_seq.NEXTVAL
           ,pi_nmu_name
           ,pi_nmu_email
           ,pi_nmu_user_id
           );
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO create_mail_user_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END create_mail_user;                             
  
  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE update_mail_user(pi_old_nmu_id               IN     nm_mail_users.nmu_id%TYPE
                            ,pi_old_nmu_name             IN     nm_mail_users.nmu_name%TYPE
                            ,pi_old_nmu_email            IN     nm_mail_users.nmu_email_address%TYPE
                            ,pi_old_nmu_user_id          IN     nm_mail_users.nmu_hus_user_id%TYPE
                            ,pi_new_nmu_id               IN     nm_mail_users.nmu_id%TYPE
                            ,pi_new_nmu_name             IN     nm_mail_users.nmu_name%TYPE
                            ,pi_new_nmu_email            IN     nm_mail_users.nmu_email_address%TYPE
                            ,pi_new_nmu_user_id          IN     nm_mail_users.nmu_hus_user_id%TYPE
                            ,po_message_severity            OUT hig_codes.hco_code%TYPE
                            ,po_message_cursor              OUT sys_refcursor)
  IS
    --
    lr_db_rec        nm_mail_users%ROWTYPE;
    lv_upd           VARCHAR2(1) := 'N';
    --
    PROCEDURE get_db_rec
      IS
    BEGIN
      --
      SELECT *
        INTO lr_db_rec
        FROM nm_mail_users
       WHERE nmu_id = pi_old_nmu_id
         FOR UPDATE NOWAIT;
      --
    EXCEPTION
      WHEN NO_DATA_FOUND
       THEN
          --
          hig.raise_ner(pi_appl               => 'HIG'
                       ,pi_id                 => 85
                       ,pi_supplementary_info => 'Mail User Id does not exist');
          --
    END get_db_rec;
    --
  BEGIN
    --
    SAVEPOINT update_mail_user_sp;
    --
    awlrs_util.check_historic_mode;   
    --
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Mail User Id'
                               ,pi_parameter_value => pi_new_nmu_id);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Name'
                               ,pi_parameter_value => pi_new_nmu_name);
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Email'
                               ,pi_parameter_value => pi_new_nmu_email);
    --
    get_db_rec;
    --
    /*
    ||Compare Old with DB
    */
    IF lr_db_rec.nmu_id != pi_old_nmu_id
     OR (lr_db_rec.nmu_id IS NULL AND pi_old_nmu_id IS NOT NULL)
     OR (lr_db_rec.nmu_id IS NOT NULL AND pi_old_nmu_id IS NULL)
     --
     OR (UPPER(lr_db_rec.nmu_name) != UPPER(pi_old_nmu_name))
     OR (UPPER(lr_db_rec.nmu_name) IS NULL AND UPPER(pi_old_nmu_name) IS NOT NULL)
     OR (UPPER(lr_db_rec.nmu_name) IS NOT NULL AND UPPER(pi_old_nmu_name) IS NULL)
     --
     OR (UPPER(lr_db_rec.nmu_email_address) != UPPER(pi_old_nmu_email))
     OR (UPPER(lr_db_rec.nmu_email_address) IS NULL AND UPPER(pi_old_nmu_email) IS NOT NULL)
     OR (UPPER(lr_db_rec.nmu_email_address) IS NOT NULL AND UPPER(pi_old_nmu_email) IS NULL)
     --
     OR (lr_db_rec.nmu_hus_user_id != pi_old_nmu_user_id)
     OR (lr_db_rec.nmu_hus_user_id IS NULL AND pi_old_nmu_user_id IS NOT NULL)
     OR (lr_db_rec.nmu_hus_user_id IS NOT NULL AND pi_old_nmu_user_id IS NULL)
     --
     THEN
        --Updated by another user
        hig.raise_ner(pi_appl => 'AWLRS'
                     ,pi_id   => 24);
    ELSE
      /*
      ||Compare Old with New
      */
      IF UPPER(pi_old_nmu_name) != UPPER(pi_new_nmu_name)
       OR (UPPER(pi_old_nmu_name) IS NULL AND UPPER(pi_new_nmu_name) IS NOT NULL)
       OR (UPPER(pi_old_nmu_name) IS NOT NULL AND UPPER(pi_new_nmu_name) IS NULL)
       THEN
         IF name_exists(pi_nmu_name => pi_new_nmu_name) 
          THEN
            hig.raise_ner(pi_appl => 'HIG'
                         ,pi_id   => 64
                         ,pi_supplementary_info  => 'Name:  '||pi_new_nmu_name);
         ELSE
            lv_upd := 'Y';                  
         END IF; 
      END IF;
      --
      IF UPPER(pi_old_nmu_email) != UPPER(pi_new_nmu_email)
       OR (UPPER(pi_old_nmu_email) IS NULL AND UPPER(pi_new_nmu_email) IS NOT NULL)
       OR (UPPER(pi_old_nmu_email) IS NOT NULL AND UPPER(pi_new_nmu_email) IS NULL)
       THEN
         IF email_exists(pi_nmu_email => pi_new_nmu_email) 
          THEN
            hig.raise_ner(pi_appl => 'HIG'
                         ,pi_id   => 64
                         ,pi_supplementary_info  => 'Email:  '||pi_new_nmu_email);
         ELSE
            lv_upd := 'Y';                
         END IF; 
      END IF;
      --
      IF pi_old_nmu_user_id != pi_new_nmu_user_id
       OR (pi_old_nmu_user_id IS NULL AND pi_new_nmu_user_id IS NOT NULL)
       OR (pi_old_nmu_user_id IS NOT NULL AND pi_new_nmu_user_id IS NULL)
       THEN
         IF user_id_exists(pi_nmu_hus_user_id => pi_new_nmu_user_id) 
          THEN
            hig.raise_ner(pi_appl => 'HIG'
                         ,pi_id   => 64
                         ,pi_supplementary_info  => 'User Id:  '||pi_new_nmu_user_id);
         ELSE
            lv_upd := 'Y';                
         END IF;
      END IF;
      --
      IF lv_upd = 'N'
       THEN
          --There are no changes to be applied
          hig.raise_ner(pi_appl => 'AWLRS'
                       ,pi_id   => 25);
      ELSE
        --
        UPDATE nm_mail_users
           SET nmu_name          = UPPER(pi_new_nmu_name)
              ,nmu_email_address = UPPER(pi_new_nmu_email)
              ,nmu_hus_user_id   = pi_new_nmu_user_id
         WHERE nmu_id            = pi_new_nmu_id;
        --
        awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                             ,po_cursor           => po_message_cursor);
        --
      END IF;
    END IF;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO update_mail_user_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor);
  END update_mail_user;                                                        

  --
  -----------------------------------------------------------------------------
  --
  PROCEDURE delete_mail_user(pi_nmu_id                   IN     nm_mail_users.nmu_id%TYPE
                            ,po_message_severity            OUT hig_codes.hco_code%TYPE
                            ,po_message_cursor              OUT sys_refcursor)
  IS
  --
  BEGIN
    --
    SAVEPOINT delete_mail_user_sp;
    --
    awlrs_util.check_historic_mode; 
    --  
    --Firstly we need to check the caller has the correct roles to continue--
    IF NOT privs_check(pi_role_name  => cv_hig_admin)
      THEN
         hig.raise_ner(pi_appl => 'HIG'
                      ,pi_id   => 86);
    END IF;
    --
    awlrs_util.validate_notnull(pi_parameter_desc  => 'Mail User Id'
                               ,pi_parameter_value => pi_nmu_id);
    --
    IF NOT mail_id_exists(pi_nmu_id => pi_nmu_id) 
     THEN
        hig.raise_ner(pi_appl => 'HIG'
                     ,pi_id   => 30
                     ,pi_supplementary_info  => 'Mail User Id:  '||pi_nmu_id);
    END IF;
    --
    /*
    ||delete from nm_mail_users.
    */
    DELETE 
      FROM nm_mail_users
     WHERE nmu_id = pi_nmu_id;
    --
    awlrs_util.get_default_success_cursor(po_message_severity => po_message_severity
                                         ,po_cursor           => po_message_cursor);
    --
  EXCEPTION
    WHEN OTHERS
     THEN
        ROLLBACK TO delete_mail_user_sp;
        awlrs_util.handle_exception(po_message_severity => po_message_severity
                                   ,po_cursor           => po_message_cursor); 
  --
  END delete_mail_user;                                                                                                                                        
  --
 
END awlrs_alerts_api;
/


