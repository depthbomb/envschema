package generate

import (
	"bytes"
	"fmt"
	"github.com/depthbomb/envschema"
	"strconv"
	"strings"
)

func writeReportLoader(source *bytes.Buffer, schema envschema.Schema, typeName string, names, types []string, optional []bool) {
	fmt.Fprintf(source, "\nfunc LoadWithReport(input envschema.Source) (%s,envschema.LoadReport,error) {\n", typeName)
	source.WriteString("values,report,err:=envschema.LoadWithReport(generatedSchema,input)\n")
	fmt.Fprintf(source, "if err!=nil{return %s{},report,err}\nvar config %s\nvar failures []error\n", typeName, typeName)
	if len(schema.Variables) == 0 {
		source.WriteString("_ = values\n")
	}
	for i, variable := range schema.Variables {
		base := types[i]
		if optional[i] {
			base = strings.TrimPrefix(base, "*")
		}
		fmt.Fprintf(source, "if _,present:=values[%q];present {\n", variable.Name)
		if variable.Rule.Kind == envschema.KindCustom && !variable.Rule.Redact {
			fmt.Fprintf(source, "value,_,err:=envschema.ReadText[%s](generatedSchema.Variables[%d].Rule,%q,func(name string)(string,bool){\nvalue,present:=values[name].(string)\n\nreturn value,present\n})\n", base, i, variable.Name)
		} else {
			fmt.Fprintf(source, "value,err:=envschema.ValueAs[%s](values,%s)\n", base, strconv.Quote(variable.Name))
		}
		address := ""
		if optional[i] {
			address = "&"
		}
		fmt.Fprintf(source, "if err!=nil{failures=append(failures,err)}else{config.%s=%svalue}\n}\n", names[i], address)
	}
	fmt.Fprintf(source, "if err:=envschema.JoinErrors(failures...);err!=nil{return %s{},report,err}\nreturn config,report,nil\n}\n", typeName)
}
